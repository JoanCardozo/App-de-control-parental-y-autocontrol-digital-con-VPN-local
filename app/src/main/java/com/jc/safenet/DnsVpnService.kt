package com.jc.safenet

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.Executors

class DnsVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.jc.safenet.START"
        const val ACTION_STOP = "com.jc.safenet.STOP"
        private const val VPN_ADDRESS = "10.111.0.2"
        private const val VPN_DNS = "10.111.0.1"
        @Volatile var isRunning = false

        // DNS que ya filtran adultos (segunda capa). Si el primero falla, usa el segundo.
        private val UPSTREAMS = listOf("1.1.1.3", "1.0.0.3")

        // IPs de DNS cifrado (DoH/DoT) conocidos: se "tiran al vacío" para que
        // ningún navegador pueda saltarse el filtro con DNS propio.
        private val BLACKHOLE_IPS = listOf(
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",
            "1.1.1.3", "1.0.0.3", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15"
        )
    }

    private var tun: ParcelFileDescriptor? = null
    private val pool = Executors.newFixedThreadPool(8)
    private var blocklist = LongArray(0)
    private val writeLock = Any()
    private val googleRegex = Regex("^(www\\.)?google\\.[a-z]{2,3}(\\.[a-z]{2})?$")

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        goForeground()
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        startVpn()
        return START_STICKY
    }

    // Servicio en primer plano: Android lo trata como importante y no lo cierra
    // cuando se desliza la app en "apps recientes".
    private fun goForeground() {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel("safenet", "Protección SafeNet", NotificationManager.IMPORTANCE_LOW)
            )
            val open = PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
            )
            val n = Notification.Builder(this, "safenet")
                .setContentTitle("SafeNet activo")
                .setContentText("Protección funcionando")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(open)
                .setOngoing(true)
                .build()
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(1, n)
            }
        } catch (_: Exception) { }
    }

    private fun startVpn() {
        if (isRunning) return
        blocklist = loadBlocklist()

        val b = Builder()
            .setSession("SafeNet")
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(VPN_DNS)
            .addRoute(VPN_DNS, 32)      // solo las consultas DNS pasan por la app
            .setBlocking(true)
        b.addDisallowedApplication(packageName) // el tráfico de esta app sale directo
        BLACKHOLE_IPS.forEach { b.addRoute(it, 32) }

        tun = b.establish() ?: return
        isRunning = true
        Thread { loop() }.start()
    }

    private fun stopVpn() {
        isRunning = false
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun loop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        try {
            while (isRunning) {
                val n = input.read(buf)
                if (n <= 0) continue
                val packet = buf.copyOf(n)
                pool.execute {
                    try { handle(packet, output) } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {
        } finally {
            stopVpn()
        }
    }

    private fun u16(b: ByteArray, o: Int) =
        ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun handle(p: ByteArray, out: FileOutputStream) {
        if (p.size < 28) return
        if ((p[0].toInt() shr 4) != 4) return          // solo IPv4
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (p[9].toInt() != 17) return                  // solo UDP; lo demás se descarta
        if (p.size < ihl + 8) return
        val srcPort = u16(p, ihl)
        val dstPort = u16(p, ihl + 2)
        val udpLen = u16(p, ihl + 4)
        if (dstPort != 53) return

        val dstIp = p.copyOfRange(16, 20)
        val dstText = dstIp.joinToString(".") { (it.toInt() and 0xFF).toString() }
        if (dstText != VPN_DNS) return

        val end = minOf(p.size, ihl + udpLen)
        val query = p.copyOfRange(ihl + 8, end)
        val answer = resolve(query) ?: return
        val srcIp = p.copyOfRange(12, 16)
        val reply = buildUdpPacket(dstIp, srcIp, 53, srcPort, answer)
        synchronized(writeLock) { out.write(reply) }
    }

    // ---------- Lógica DNS ----------

    private fun resolve(q: ByteArray): ByteArray? {
        if (q.size < 17) return null
        var pos = 12
        val labels = ArrayList<String>()
        while (pos < q.size) {
            val l = q[pos].toInt() and 0xFF
            if (l == 0) { pos++; break }
            if ((l and 0xC0) != 0) return null
            if (pos + 1 + l > q.size) return null
            labels.add(String(q, pos + 1, l, Charsets.US_ASCII).lowercase())
            pos += 1 + l
        }
        if (pos + 4 > q.size) return null
        val qType = u16(q, pos)
        val qEnd = pos + 4
        val name = labels.joinToString(".")

        if (isBlocked(name)) return nxdomain(q, qEnd)
        safeSearchTarget(name)?.let { return safeSearchAnswer(q, qEnd, qType, it) }
        return forward(q)
    }

    // Huella de 64 bits de un dominio (así 950.000 dominios ocupan ~8 MB)
    private fun h64(s: String): Long {
        var h = -3750763034362895579L
        for (ch in s) {
            h = h xor ch.code.toLong()
            h *= 1099511628211L
        }
        return h
    }

    private fun isBlocked(name: String): Boolean {
        var c = name
        while (true) {
            if (java.util.Arrays.binarySearch(blocklist, h64(c)) >= 0) return true
            val i = c.indexOf('.')
            if (i < 0) return false
            c = c.substring(i + 1)
        }
    }

    private fun nxdomain(q: ByteArray, qEnd: Int): ByteArray {
        val r = q.copyOf(qEnd)
        r[2] = 0x81.toByte(); r[3] = 0x83.toByte() // respuesta + "dominio no existe"
        for (i in 6..11) r[i] = 0
        return r
    }

    private fun safeSearchTarget(n: String): String? = when {
        googleRegex.matches(n) -> "forcesafesearch.google.com"
        n == "bing.com" || n == "www.bing.com" -> "strict.bing.com"
        n == "duckduckgo.com" || n == "www.duckduckgo.com" -> "safe.duckduckgo.com"
        else -> null
    }

    private fun safeSearchAnswer(q: ByteArray, qEnd: Int, qType: Int, target: String): ByteArray {
        val ips = if (qType == 1) {
            try {
                InetAddress.getAllByName(target).filterIsInstance<Inet4Address>()
            } catch (_: Exception) { emptyList() }
        } else emptyList()

        val o = ByteArrayOutputStream()
        o.write(q, 0, 2)
        o.write(0x81); o.write(0x80)
        o.write(0); o.write(1)
        o.write(0); o.write(ips.size)
        o.write(0); o.write(0); o.write(0); o.write(0)
        o.write(q, 12, qEnd - 12)
        for (ip in ips) {
            o.write(0xC0); o.write(0x0C)
            o.write(0); o.write(1); o.write(0); o.write(1)
            o.write(0); o.write(0); o.write(0); o.write(60)
            o.write(0); o.write(4)
            o.write(ip.address)
        }
        return o.toByteArray()
    }

    // Pregunta al primer DNS; si no responde, prueba con el segundo
    private fun forward(q: ByteArray): ByteArray? {
        for (ip in UPSTREAMS) {
            try {
                return DatagramSocket().use { s ->
                    s.soTimeout = 2500
                    s.send(DatagramPacket(q, q.size, InetAddress.getByName(ip), 53))
                    val buf = ByteArray(4096)
                    val rp = DatagramPacket(buf, buf.size)
                    s.receive(rp)
                    buf.copyOf(rp.length)
                }
            } catch (_: Exception) { }
        }
        return null
    }

    // ---------- Armar el paquete de respuesta ----------

    private fun buildUdpPacket(src: ByteArray, dst: ByteArray, sp: Int, dp: Int, data: ByteArray): ByteArray {
        val total = 28 + data.size
        val r = ByteArray(total)
        r[0] = 0x45
        r[2] = (total shr 8).toByte(); r[3] = total.toByte()
        r[6] = 0x40
        r[8] = 64; r[9] = 17
        System.arraycopy(src, 0, r, 12, 4)
        System.arraycopy(dst, 0, r, 16, 4)
        var sum = 0
        for (i in 0 until 20 step 2) sum += u16(r, i)
        while ((sum shr 16) != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val ck = sum.inv() and 0xFFFF
        r[10] = (ck shr 8).toByte(); r[11] = ck.toByte()
        r[20] = (sp shr 8).toByte(); r[21] = sp.toByte()
        r[22] = (dp shr 8).toByte(); r[23] = dp.toByte()
        val ul = 8 + data.size
        r[24] = (ul shr 8).toByte(); r[25] = ul.toByte()
        System.arraycopy(data, 0, r, 28, data.size)
        return r
    }

    private fun loadBlocklist(): LongArray {
        var arr = LongArray(1_100_000)
        var n = 0
        assets.open("blocklist.txt").bufferedReader().useLines { lines ->
            lines.forEach { raw ->
                val line = raw.substringBefore('#').trim().lowercase()
                if (line.isNotEmpty()) {
                    if (n == arr.size) arr = arr.copyOf(n * 2)
                    arr[n++] = h64(line.split(' ', '\t').last())
                }
            }
        }
        val r = arr.copyOf(n)
        r.sort()
        return r
    }
}