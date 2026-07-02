package com.example.wifinanbridge

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.example.wifinanbridge.ui.theme.WiFINaNBridgeTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var nanPublisher: NanPublisher
    private var tcpServer: TcpServer? = null
    
    private var sessionCount by mutableIntStateOf(0)

    private val requestPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
            val allGranted = permissions.entries.all { it.value }
            if (allGranted) {
                startServices()
            } else {
                Log.e("MainActivity", "Permissions not granted")
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        nanPublisher = NanPublisher(this)
        nanPublisher.onSessionCountChanged = { count ->
            sessionCount = count
        }
        
        enableEdgeToEdge()
        setContent {
            WiFINaNBridgeTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Box(modifier = Modifier.fillMaxSize().padding(innerPadding), contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("Wi-Fi NAN Bridge is running", style = MaterialTheme.typography.headlineSmall)
                            Spacer(modifier = Modifier.height(16.dp))
                            Text("Active Advertising Sessions: $sessionCount", style = MaterialTheme.typography.bodyLarge)
                        }
                    }
                }
            }
        }

        checkAndRequestPermissions()
    }

    private fun checkAndRequestPermissions() {
        val requiredPermissions = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requiredPermissions.add(Manifest.permission.NEARBY_WIFI_DEVICES)
        }

        val missingPermissions = requiredPermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isNotEmpty()) {
            requestPermissionLauncher.launch(missingPermissions.toTypedArray())
        } else {
            startServices()
        }
    }

    private fun startServices() {
        nanPublisher.attach()

        nanPublisher.onFailure = { droneId, reason ->
            val errorCmd = org.json.JSONObject().apply {
                put("type", "ERROR")
                put("drone_id", droneId)
                put("reason", reason)
            }
            tcpServer?.broadcast(errorCmd.toString())
        }

        tcpServer = TcpServer(8080) { cmd ->
            val type = cmd.optString("type")
            val droneId = cmd.optString("drone_id")

            when (type) {
                "CONFIG" -> {
                    nanPublisher.configureDrone(droneId)
                }
                "PAYLOAD" -> {
                    val payload = cmd.optString("payload")
                    nanPublisher.updatePayload(droneId, payload)
                }
                "STOP" -> {
                    nanPublisher.stopDrone(droneId)
                }
                "RESET" -> {
                    nanPublisher.reset()
                }
                "STOP_ALL" -> {
                    nanPublisher.stopAllDrones()
                }
            }
        }

        lifecycleScope.launch {
            tcpServer?.start()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        tcpServer?.stop()
        nanPublisher.destroy()
    }
}