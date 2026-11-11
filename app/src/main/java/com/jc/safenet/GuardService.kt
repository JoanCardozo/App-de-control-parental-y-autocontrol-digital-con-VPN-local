package com.jc.safenet

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

class GuardService : AccessibilityService() {

    companion object {
        // La propia app lo activa un momento cuando ella misma pide el permiso de VPN
        @Volatile var allowVpnDialog = false
    }

    override fun onAccessibilityEvent(e: AccessibilityEvent?) {
        if (e == null || !Guard.isEnabled(this)) return
        val pkg = e.packageName?.toString() ?: return
        if (pkg == packageName) return

        // Aviso de "esta app quiere crear una VPN": se cierra (evita usar otra VPN)
        if (pkg == "com.android.vpndialogs") {
            if (!allowVpnDialog) kick()
            return
        }

        if (e.text.any { it?.contains("safenet", true) == true }) { kick(); return }
        val root = rootInActiveWindow ?: return
        if (mentions(root, 0)) kick()
    }

    private fun mentions(n: AccessibilityNodeInfo?, depth: Int): Boolean {
        if (n == null || depth > 25) return false
        if (n.text?.contains("safenet", true) == true) return true
        if (n.contentDescription?.contains("safenet", true) == true) return true
        for (i in 0 until n.childCount) {
            if (mentions(n.getChild(i), depth + 1)) return true
        }
        return false
    }

    private fun kick() {
        performGlobalAction(GLOBAL_ACTION_HOME)
    }

    override fun onInterrupt() {}
}