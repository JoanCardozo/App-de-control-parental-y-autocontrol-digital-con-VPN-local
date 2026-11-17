package com.jc.safenet

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val ok = intent.action == Intent.ACTION_BOOT_COMPLETED ||
                intent.action == Intent.ACTION_MY_PACKAGE_REPLACED
        if (ok && Guard.isEnabled(context) && VpnService.prepare(context) == null) {
            context.startForegroundService(
                Intent(context, DnsVpnService::class.java)
                    .setAction(DnsVpnService.ACTION_START)
            )
        }
    }
}