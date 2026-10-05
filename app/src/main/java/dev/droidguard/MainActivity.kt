package dev.droidguard

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.util.concurrent.Executors

/** Deliberately plain: one button, one text view. The scanner is the project. */
class MainActivity : Activity() {
    private var service: IScanService? = null
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var output: TextView

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = IScanService.Stub.asInterface(binder)
        }
        override fun onServiceDisconnected(name: ComponentName) {
            service = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        output = TextView(this).apply { setTextIsSelectable(true); setPadding(32, 32, 32, 32) }
        val button = Button(this).apply { text = "Scan device"; setOnClickListener { scan() } }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(button)
            addView(ScrollView(this@MainActivity).apply { addView(output) })
        })
        bindService(Intent(this, ScanService::class.java), conn, Context.BIND_AUTO_CREATE)
    }

    private fun scan() {
        val s = service ?: run { output.text = "service not bound yet"; return }
        output.text = "scanning..."
        // runScan is a synchronous Binder call; never on the main thread.
        worker.execute {
            val text = try {
                JSONObject(s.runScan()).toString(2)
            } catch (e: Exception) {
                "scan failed: $e"
            }
            runOnUiThread { output.text = text }
        }
    }

    override fun onDestroy() {
        unbindService(conn)
        worker.shutdown()
        super.onDestroy()
    }
}
