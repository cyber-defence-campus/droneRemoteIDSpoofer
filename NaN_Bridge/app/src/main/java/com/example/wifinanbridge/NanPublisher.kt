package com.example.wifinanbridge

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareSession
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import androidx.core.content.ContextCompat

class NanPublisher(private val context: Context) {

    private var wifiAwareManager: WifiAwareManager? = null
    private var awareSession: WifiAwareSession? = null
    
    // Map of drone_id -> PublishSession
    private val publishSessions = mutableMapOf<String, PublishDiscoverySession>()
    private val pendingConfigurations = mutableSetOf<String>()

    var onFailure: ((String, String) -> Unit)? = null
    var onSessionCountChanged: ((Int) -> Unit)? = null

    init {
        val pm = context.packageManager
        if (pm.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)) {
            wifiAwareManager = context.getSystemService(Context.WIFI_AWARE_SERVICE) as WifiAwareManager?
        } else {
            Log.e("NanPublisher", "Wi-Fi Aware is not supported on this device.")
        }
    }

    @SuppressLint("MissingPermission")
    fun attach() {
        synchronized(this) {
            if (wifiAwareManager == null) return
            if (awareSession != null) {
                Log.i("NanPublisher", "Wi-Fi Aware already attached")
                return
            }
        }
        
        if (ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(context, android.Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
            Log.e("NanPublisher", "Missing required permissions for Wi-Fi Aware")
            return
        }

        wifiAwareManager?.attach(object : AttachCallback() {
            override fun onAttached(session: WifiAwareSession?) {
                super.onAttached(session)
                synchronized(this@NanPublisher) {
                    awareSession = session
                }
                Log.i("NanPublisher", "Wi-Fi Aware session attached")
            }

            override fun onAttachFailed() {
                super.onAttachFailed()
                Log.e("NanPublisher", "Wi-Fi Aware attach failed")
                onFailure?.invoke("SYSTEM", "Wi-Fi Aware attach failed. Is Wi-Fi on?")
            }
        }, Handler(Looper.getMainLooper()))
    }

    @SuppressLint("MissingPermission")
    fun configureDrone(droneId: String) {
        val currentAwareSession = synchronized(this) {
            if (awareSession == null) {
                return@synchronized null
            }
            
            if (publishSessions.containsKey(droneId)) {
                Log.i("NanPublisher", "Drone $droneId is already configured.")
                return
            }

            if (pendingConfigurations.contains(droneId)) {
                Log.i("NanPublisher", "Configuration for $droneId is already pending.")
                return
            }

            pendingConfigurations.add(droneId)
            awareSession
        }

        if (currentAwareSession == null) {
            Log.w("NanPublisher", "Cannot configure drone, Aware session not attached.")
            attach()
            return
        }

        // ASTM F3411-22 specifies Service Name org.opendroneid.remoteid
        val config = PublishConfig.Builder()
            .setServiceName("org.opendroneid.remoteid")
            .build()

        currentAwareSession.publish(config, object : DiscoverySessionCallback() {
            override fun onPublishStarted(session: PublishDiscoverySession) {
                super.onPublishStarted(session)
                Log.i("NanPublisher", "Publish started for drone $droneId")
                val size = synchronized(this@NanPublisher) {
                    pendingConfigurations.remove(droneId)
                    publishSessions[droneId] = session
                    publishSessions.size
                }
                onSessionCountChanged?.invoke(size)
            }

            override fun onSessionConfigFailed() {
                super.onSessionConfigFailed()
                Log.e("NanPublisher", "Publish failed for drone $droneId")
                val shouldReset = synchronized(this@NanPublisher) {
                    pendingConfigurations.remove(droneId)
                    publishSessions.size >= 7 // Typical hardware limit is around 8
                }
                
                if (shouldReset) {
                    Log.w("NanPublisher", "Possible session limit reached, triggering reset.")
                    reset()
                }

                onFailure?.invoke(droneId, "Session config failed (limit reached?)")
            }

            override fun onSessionTerminated() {
                super.onSessionTerminated()
                Log.w("NanPublisher", "Session terminated for drone $droneId")
                val size = synchronized(this@NanPublisher) {
                    if (publishSessions.remove(droneId) != null) {
                        publishSessions.size
                    } else {
                        -1
                    }
                }
                if (size != -1) {
                    onSessionCountChanged?.invoke(size)
                }
            }
        }, Handler(Looper.getMainLooper()))
    }

    fun updatePayload(droneId: String, payloadBase64: String) {
        val session = synchronized(this) { publishSessions[droneId] }
        if (session == null) {
            Log.w("NanPublisher", "Cannot update payload, session for $droneId not found.")
            return
        }

        try {
            val payloadBytes = Base64.decode(payloadBase64, Base64.DEFAULT)
            // The ASTM Remote ID payloads are put into the Service Specific Info (SSI)
            session.updatePublish(
                PublishConfig.Builder()
                    .setServiceName("org.opendroneid.remoteid")
                    .setServiceSpecificInfo(payloadBytes)
                    .build()
            )
            Log.d("NanPublisher", "Payload updated for $droneId (${payloadBytes.size} bytes)")
        } catch (e: Exception) {
            Log.e("NanPublisher", "Failed to decode/update payload", e)
        }
    }

    fun stopDrone(droneId: String) {
        val (session, size) = synchronized(this) {
            pendingConfigurations.remove(droneId)
            val s = publishSessions.remove(droneId)
            s to publishSessions.size
        }
        if (session != null) {
            session.close()
            Log.i("NanPublisher", "Stopped publishing for drone $droneId")
            onSessionCountChanged?.invoke(size)
        }
    }

    fun stopAllDrones() {
        val sessionsToClose: List<PublishDiscoverySession>
        synchronized(this) {
            pendingConfigurations.clear()
            sessionsToClose = publishSessions.values.toList()
            publishSessions.clear()
        }
        sessionsToClose.forEach { it.close() }
        onSessionCountChanged?.invoke(0)
        Log.i("NanPublisher", "Stopped all drone sessions")
    }

    fun reset() {
        Log.i("NanPublisher", "Resetting NanPublisher...")
        destroy()
        // Wait a bit before re-attaching to give hardware time to breathe
        Handler(Looper.getMainLooper()).postDelayed({
            attach()
        }, 1000)
    }

    fun destroy() {
        stopAllDrones()
        synchronized(this) {
            awareSession?.close()
            awareSession = null
        }
        Log.i("NanPublisher", "NanPublisher destroyed")
    }
}
