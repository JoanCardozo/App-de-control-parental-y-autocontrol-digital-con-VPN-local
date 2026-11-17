package com.jc.safenet

import android.accessibilityservice.AccessibilityService
import android.os.SystemClock
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

class GuardService : AccessibilityService() {

    companion object {
        // La propia app lo activa un momento cuando ella misma pide el permiso de VPN
        @Volatile var allowVpnDialog = false

        private val SETTINGS = setOf(
            "com.android.settings", "com.miui.securitycenter", "com.miui.packageinstaller",
            "com.google.android.packageinstaller", "com.android.packageinstaller",
            "com.miui.powerkeeper"
        )

        private val BROWSERS = setOf(
            "com.android.chrome", "org.mozilla.firefox", "com.brave.browser",
            "com.opera.browser", "com.opera.mini.native", "com.microsoft.emmx",
            "com.sec.android.app.sbrowser", "com.mi.globalbrowser", "com.android.browser",
            "com.duckduckgo.mobile.android", "com.google.android.googlequicksearchbox",
            "com.kiwibrowser.browser", "com.vivaldi.browser", "com.UCMobile.intl", "mark.via.gp"
        )

        // Palabras que cuentan si EMPIEZAN una palabra (porn -> pornhub, porno, pornografía)
        private val PREFIX = listOf(
            "porn", "xnxx", "xvideo", "xhamster", "hentai", "onlyfans", "rule34", "redtube",
            "youporn", "brazzers", "chaturbate", "stripchat", "bongacams", "livejasmin",
            "spankbang", "eporner", "fapello", "sexcam", "camgirl", "blowjob", "handjob",
            "gangbang", "creampie", "cumshot", "follando", "putaria", "nacktbilder",
            "sexfilm", "sexvideo", "sex video", "free sex", "sex tape", "sex cam", "anal sex",
            "naked girls", "nude girls", "videos de sexo", "sexo anal", "sexo en vivo",
            "sexo gratis", "sexo oral", "mujeres desnudas", "chicas desnudas", "film x",
            "video sexe", "vidéos de sexe", "sesso anale", "video sesso", "секс видео"
        )

        // Palabras que deben aparecer completas (para no confundir "milf" con "Milford")
        private val WORDS = listOf("xxx", "milf", "nsfw", "tetas", "putas")

        // Japonés, chino, coreano, ruso y árabe (se buscan tal cual)
        private val PLAIN = listOf(
            "エロ", "ポルノ", "セックス", "無修正", "アダルト動画", "ハメ撮り",
            "色情", "成人视频", "成人影片", "黄色网站", "黃色網站", "做爱", "性爱", "無碼", "无码",
            "야동", "포르노", "섹스", "порно", "сексвидео",
            "سكس", "افلام سكس", "افلام جنسية"
        )

        private val ADULT: Regex = Regex(
            listOf(
                "\\b(?:" + PREFIX.joinToString("|") { Regex.escape(it) } + ")",
                "\\b(?:" + WORDS.joinToString("|") { Regex.escape(it) } + ")\\b",
                "(?:" + PLAIN.joinToString("|") { Regex.escape(it) } + ")"
            ).joinToString("|"),
            RegexOption.IGNORE_CASE
        )
    }

    private var lastScan = 0L
    private var lastKick = 0L
    private var visited = 0

    override fun onAccessibilityEvent(e: AccessibilityEvent?) {
        if (e == null || !Guard.isEnabled(this)) return
        val pkg = e.packageName?.toString() ?: return
        if (pkg == packageName) return

        // Aviso de "esta app quiere crear una VPN": se cierra (evita usar otra VPN)
        if (pkg == "com.android.vpndialogs") {
            if (!allowVpnDialog) kick()
            return
        }

        // Navegadores: palabras +18 escritas o visibles en pantalla
        if (pkg in BROWSERS) {
            if (e.text.any { hasAdult(it?.toString()) }) { kick(); return }
            if (e.eventType == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) return
            val now = SystemClock.uptimeMillis()
            if (now - lastScan < 700) return
            lastScan = now
            val root = rootInActiveWindow ?: return
            visited = 0
            if (scan(root, 0)) kick()
            return
        }

        // Pantallas de Ajustes / instalador: si aparece "SafeNet", te saca
        if (pkg in SETTINGS) {
            if (e.text.any { it?.contains("safenet", true) == true }) { kick(); return }
            val root = rootInActiveWindow ?: return
            visited = 0
            if (mentionsSafeNet(root, 0)) kick()
        }
    }

    private fun hasAdult(s: String?): Boolean = s != null && ADULT.containsMatchIn(s)

    private fun scan(n: AccessibilityNodeInfo?, depth: Int): Boolean {
        if (n == null || depth > 40 || visited > 1500) return false
        visited++
        if (hasAdult(n.text?.toString()) || hasAdult(n.contentDescription?.toString())) return true
        for (i in 0 until n.childCount) {
            if (scan(n.getChild(i), depth + 1)) return true
        }
        return false
    }

    private fun mentionsSafeNet(n: AccessibilityNodeInfo?, depth: Int): Boolean {
        if (n == null || depth > 25 || visited > 1500) return false
        visited++
        if (n.text?.contains("safenet", true) == true) return true
        if (n.contentDescription?.contains("safenet", true) == true) return true
        for (i in 0 until n.childCount) {
            if (mentionsSafeNet(n.getChild(i), depth + 1)) return true
        }
        return false
    }

    private fun kick() {
        val now = SystemClock.uptimeMillis()
        if (now - lastKick < 800) return
        lastKick = now
        performGlobalAction(GLOBAL_ACTION_HOME)
    }

    override fun onInterrupt() {}
}