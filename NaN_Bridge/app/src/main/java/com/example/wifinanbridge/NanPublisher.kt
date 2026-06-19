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
        if (wifiAwareManager == null) return
        
        if (ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(context, android.Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
            Log.e("NanPublisher", "Missing required permissions for Wi-Fi Aware")
            return
        }

        wifiAwareManager?.attach(object : AttachCallback() {
            override fun onAttached(session: WifiAwareSession?) {
                super.onAttached(session)
                awareSession = session
                Log.i("NanPublisher", "Wi-Fi Aware session attached")
            }

            override fun onAttachFailed() {
                super.onAttachFailed()
                Log.e("NanPublisher", "Wi-Fi Aware attach failed")
            }
        }, Handler(Looper.getMainLooper()))
    }

    @SuppressLint("MissingPermission")
    fun configureDrone(droneId: String) {
        if (awareSession == null) {
            Log.w("NanPublisher", "Cannot configure drone, Aware session not attached.")
            return
        }
        
        if (publishSessions.containsKey(droneId)) {
            Log.i("NanPublisher", "Drone $droneId is already configured.")
            return
        }

        // ASTM F3411-22 specifies Service Name org.opendroneid.rid
        val config = PublishConfig.Builder()
            .setServiceName("org.opendroneid.remoteid")
            .build()

        awareSession?.publish(config, object : DiscoverySessionCallback() {
            override fun onPublishStarted(session: PublishDiscoverySession) {
                super.onPublishStarted(session)
                Log.i("NanPublisher", "Publish started for drone $droneId")
                publishSessions[droneId] = session
            }

            override fun onSessionConfigFailed() {
                super.onSessionConfigFailed()
                Log.e("NanPublisher", "Publish failed for drone $droneId")
            }
        }, Handler(Looper.getMainLooper()))
    }

    fun updatePayload(droneId: String, payloadBase64: String) {
        val session = publishSessions[droneId]
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

    fun destroy() {
        publishSessions.values.forEach { it.close() }
        publishSessions.clear()
        awareSession?.close()
        awareSession = null
        Log.i("NanPublisher", "NanPublisher destroyed")
    }
}
