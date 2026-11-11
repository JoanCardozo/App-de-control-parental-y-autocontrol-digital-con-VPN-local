package com.jc.safenet

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

sealed class CheckResult {
    object Ok : CheckResult()
    data class Wrong(val left: Int) : CheckResult()
    data class Locked(val ms: Long) : CheckResult()
}

object Guard {
    const val MIN_LEN = 15
    private const val MAX_ATTEMPTS = 5
    private const val LOCK_MS = 24L * 60 * 60 * 1000   // 24 horas
    private const val ITERATIONS = 200_000

    private fun prefs(c: Context) =
        c.applicationContext.getSharedPreferences("guard", Context.MODE_PRIVATE)

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)

    private fun hash(pw: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pw.toCharArray(), salt, ITERATIONS, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    private fun bootCount(c: Context) =
        Settings.Global.getInt(c.contentResolver, Settings.Global.BOOT_COUNT, -1)

    fun isEnabled(c: Context) = prefs(c).getBoolean("enabled", false)

    /** Guarda SOLO la huella de la clave (nunca la clave) y marca la protección como activa. */
    fun enable(c: Context, pw: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        prefs(c).edit()
            .clear()
            .putString("salt", b64(salt))
            .putString("hash", b64(hash(pw, salt)))
            .putInt("attempts", 0)
            .putBoolean("enabled", true)
            .commit()
    }

    /** Borra todo (solo se llama después de verificar la clave correcta). */
    fun disable(c: Context) {
        prefs(c).edit().clear().commit()
    }

    /** Milisegundos que faltan de bloqueo. 0 = no hay bloqueo. */
    fun lockLeftMs(c: Context): Long {
        val p = prefs(c)
        val wallStart = p.getLong("lock_wall", 0L)
        if (wallStart == 0L) return 0L

        val wallLeft = LOCK_MS - (System.currentTimeMillis() - wallStart)
        val sameBoot = bootCount(c) == p.getInt("lock_boot", -2)
        val elapsedLeft = if (sameBoot)
            LOCK_MS - (SystemClock.elapsedRealtime() - p.getLong("lock_elapsed", 0L))
        else wallLeft

        // Se toma el valor que dé MÁS tiempo restante (para que cambiar la hora no sirva)
        val left = maxOf(wallLeft, elapsedLeft)
        if (left <= 0) {
            p.edit().putLong("lock_wall", 0L).putInt("attempts", 0).commit()
            return 0L
        }
        return left
    }

    fun check(c: Context, pw: String): CheckResult {
        val locked = lockLeftMs(c)
        if (locked > 0) return CheckResult.Locked(locked)

        val p = prefs(c)
        val saltS = p.getString("salt", null)
        val hashS = p.getString("hash", null)
        if (saltS == null || hashS == null) return CheckResult.Ok

        // El intento se cuenta ANTES de revisar (así no sirve cerrar la app a mitad)
        val attempts = p.getInt("attempts", 0) + 1
        p.edit().putInt("attempts", attempts).commit()

        val ok = MessageDigest.isEqual(hash(pw, unb64(saltS)), unb64(hashS))
        if (ok) {
            p.edit().putInt("attempts", 0).commit()
            return CheckResult.Ok
        }
        if (attempts >= MAX_ATTEMPTS) {
            p.edit()
                .putLong("lock_wall", System.currentTimeMillis())
                .putLong("lock_elapsed", SystemClock.elapsedRealtime())
                .putInt("lock_boot", bootCount(c))
                .putInt("attempts", 0)
                .commit()
            return CheckResult.Locked(LOCK_MS)
        }
        return CheckResult.Wrong(MAX_ATTEMPTS - attempts)
    }

    fun formatTime(ms: Long): String {
        val totalMin = (ms / 60000) + 1
        return "${totalMin / 60} h ${totalMin % 60} min"
    }
}