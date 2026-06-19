package com.example.wifinanbridge

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.ServerSocket
import java.net.Socket

class TcpServer(
    private val port: Int = 8080,
    private val onCommandReceived: (JSONObject) -> Unit
) {
    private var serverSocket: ServerSocket? = null
    private var isRunning = false

    suspend fun start() = withContext(Dispatchers.IO) {
        isRunning = true
        try {
            serverSocket = ServerSocket(port)
            Log.i("TcpServer", "Server started on port $port")
            while (isRunning) {
                val client = serverSocket?.accept()
                client?.let {
                    Log.i("TcpServer", "Client connected: ${it.inetAddress.hostAddress}")
                    handleClient(it)
                }
            }
        } catch (e: Exception) {
            Log.e("TcpServer", "Server error", e)
        } finally {
            stop()
        }
    }

    private fun handleClient(client: Socket) {
        try {
            val reader = BufferedReader(InputStreamReader(client.getInputStream()))
            var line: String?
            while (isRunning) {
                line = reader.readLine()
                if (line == null) break // Client disconnected
                
                try {
                    val json = JSONObject(line)
                    onCommandReceived(json)
                } catch (e: Exception) {
                    Log.e("TcpServer", "Failed to parse JSON: $line", e)
                }
            }
        } catch (e: Exception) {
            Log.e("TcpServer", "Client handling error", e)
        } finally {
            try {
                client.close()
            } catch (e: Exception) {
                // Ignore
            }
            Log.i("TcpServer", "Client disconnected")
        }
    }

    fun stop() {
        isRunning = false
        try {
            serverSocket?.close()
        } catch (e: Exception) {
            // Ignore
        }
        serverSocket = null
    }
}
