package com.jc.safenet

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var toggle: FrameLayout
    private lateinit var knob: View
    private lateinit var status: TextView
    private lateinit var info: TextView
    private var pendingPw: String? = null
    private var repairAsked = false

    private val dpm by lazy { getSystemService(DevicePolicyManager::class.java) }
    private val admin by lazy { ComponentName(this, AdminReceiver::class.java) }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
            GuardService.allowVpnDialog = false
            val pw = pendingPw
            pendingPw = null
            if (r.resultCode == RESULT_OK) {
                if (pw != null) finishActivation(pw)
                else if (Guard.isEnabled(this)) startVpn()
            }
            refresh()
        }

    private val adminPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            val pw = pendingPw
            if (pw != null) {
                if (dpm.isAdminActive(admin)) askVpn(pw) else {
                    pendingPw = null
                    Toast.makeText(this, "Debes activar el administrador para proteger la app", Toast.LENGTH_LONG).show()
                }
            }
            refresh()
        }

    private val notifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_main)

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        toggle = findViewById(R.id.toggle)
        knob = findViewById(R.id.knob)
        status = findViewById(R.id.status)
        info = findViewById(R.id.info)

        toggle.setOnClickListener {
            if (Guard.isEnabled(this)) askToDisable() else askNewPassword()
        }
    }

    override fun onResume() {
        super.onResume()
        if (Guard.isEnabled(this)) repairIfNeeded()
        refresh()
    }

    /** Si la protección debe estar activa, revisa que todo siga en pie y lo repara. */
    private fun repairIfNeeded() {
        // 1. Servicio guardia (accesibilidad)
        if (!accessibilityOn()) {
            if (!repairAsked) {
                repairAsked = true
                askAccessibility(true)
            }
            return
        }
        // 2. Administrador de dispositivo
        if (!dpm.isAdminActive(admin)) {
            if (!repairAsked) {
                repairAsked = true
                adminPermission.launch(adminIntent())
            }
            return
        }
        // 3. VPN
        if (!DnsVpnService.isRunning) {
            val i = VpnService.prepare(this)
            if (i == null) startVpn()
            else if (!repairAsked) {
                repairAsked = true
                GuardService.allowVpnDialog = true
                vpnPermission.launch(i)
            }
        }
    }

    // ---------- Activar ----------

    private fun askNewPassword() {
        val a = field("Clave nueva (mínimo ${Guard.MIN_LEN} caracteres)")
        val b = field("Repite la clave")
        val dialog = AlertDialog.Builder(this)
            .setTitle("Crea la clave")
            .setMessage("Quien la escriba debe guardarla. Sin ella no se puede apagar la protección.")
            .setView(box(a, b))
            .setPositiveButton("Activar", null)
            .setNegativeButton("Cancelar", null)
            .setCancelable(false)
            .create()

        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val x = a.text.toString()
                val y = b.text.toString()
                when {
                    x.length < Guard.MIN_LEN -> a.error = "Mínimo ${Guard.MIN_LEN} caracteres"
                    x != y -> b.error = "Las claves no coinciden"
                    else -> {
                        dialog.dismiss()
                        activate(x)
                    }
                }
            }
        }
        dialog.show()
    }

    /** Orden: accesibilidad -> administrador -> permiso VPN -> activar. */
    private fun activate(pw: String) {
        if (!accessibilityOn()) {
            askAccessibility(false)
            return
        }
        if (!dpm.isAdminActive(admin)) {
            pendingPw = pw
            adminPermission.launch(adminIntent())
            return
        }
        askVpn(pw)
    }

    private fun askVpn(pw: String) {
        pendingPw = pw
        val intent = VpnService.prepare(this)
        if (intent != null) {
            GuardService.allowVpnDialog = true
            vpnPermission.launch(intent)
        } else {
            pendingPw = null
            finishActivation(pw)
        }
    }

    private fun finishActivation(pw: String) {
        Guard.enable(this, pw)
        startVpn()
        refresh()
    }

    private fun adminIntent() = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
        .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin)
        .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "Evita que SafeNet se desinstale sin la clave.")

    private fun accessibilityOn(): Boolean {
        val enabled = Settings.Secure.getString(
            contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false
        val cn = ComponentName(this, GuardService::class.java)
        return enabled.split(':').any {
            it.equals(cn.flattenToString(), true) || it.equals(cn.flattenToShortString(), true)
        }
    }

    private fun askAccessibility(repair: Boolean) {
        AlertDialog.Builder(this)
            .setTitle("Activa el servicio guardia")
            .setMessage(
                (if (repair) "El servicio guardia está apagado y la protección quedó sin defensa.\n\n" else "") +
                        "En la pantalla que se abre busca SafeNet, tócalo y actívalo. " +
                        "Luego vuelve a la app" + (if (repair) "." else " y toca el botón otra vez.")
            )
            .setPositiveButton("Abrir ajustes") { _, _ ->
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
            .setCancelable(false)
            .show()
    }

    // ---------- Desactivar ----------

    private fun askToDisable() {
        val left = Guard.lockLeftMs(this)
        if (left > 0) {
            Toast.makeText(this, "Bloqueado. Intenta de nuevo en ${Guard.formatTime(left)}", Toast.LENGTH_LONG).show()
            return
        }
        val f = field("Escribe la clave")
        val dialog = AlertDialog.Builder(this)
            .setTitle("Desactivar protección")
            .setView(box(f))
            .setPositiveButton("Desactivar", null)
            .setNegativeButton("Cancelar", null)
            .create()

        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                when (val r = Guard.check(this, f.text.toString())) {
                    is CheckResult.Ok -> {
                        dialog.dismiss()
                        Guard.disable(this)
                        try { dpm.removeActiveAdmin(admin) } catch (_: Exception) {}
                        stopVpn()
                        repairAsked = false
                        refresh()
                    }
                    is CheckResult.Wrong -> {
                        f.setText("")
                        f.error = "Clave incorrecta. Te quedan ${r.left} intentos"
                    }
                    is CheckResult.Locked -> {
                        dialog.dismiss()
                        Toast.makeText(this, "Bloqueado por 24 horas", Toast.LENGTH_LONG).show()
                        refresh()
                    }
                }
            }
        }
        dialog.show()
    }

    // ---------- VPN ----------

    private fun startVpn() {
        val i = Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        startForegroundService(i)
    }

    private fun stopVpn() {
        val i = Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
        startForegroundService(i)
    }

    // ---------- Pantalla ----------

    private fun refresh() {
        val on = Guard.isEnabled(this)
        toggle.setBackgroundResource(if (on) R.drawable.bg_track_on else R.drawable.bg_track_off)
        (knob.layoutParams as FrameLayout.LayoutParams).gravity =
            Gravity.CENTER_VERTICAL or (if (on) Gravity.END else Gravity.START)
        knob.requestLayout()

        status.text = if (on) "ACTIVADO" else "DESACTIVADO"
        status.setTextColor(Color.parseColor(if (on) "#FF4D6D" else "#8A8A93"))

        val left = Guard.lockLeftMs(this)
        info.text = when {
            !on -> "Toca el botón para activar y crear la clave"
            left > 0 -> "Apagado bloqueado. Podrás intentar en ${Guard.formatTime(left)}"
            else -> "Para apagar necesitas la clave"
        }
    }

    // ---------- Ayudas ----------

    private fun field(hintText: String) = EditText(this).apply {
        hint = hintText
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        setSingleLine()
    }

    private fun box(vararg views: View): LinearLayout {
        val pad = (20 * resources.displayMetrics.density).toInt()
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad / 2, pad, 0)
            views.forEach { addView(it) }
        }
    }
}