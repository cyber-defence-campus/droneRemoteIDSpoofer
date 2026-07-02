package com.example.wifinanbridge

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections

class TcpServer(
    private val port: Int = 8080,
    private val onCommandReceived: (JSONObject) -> Unit
) {
    private var serverSocket: ServerSocket? = null
    private var isRunning = false
    private val clientWriters = Collections.synchronizedSet(mutableSetOf<PrintWriter>())
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    suspend fun start() = withContext(Dispatchers.IO) {
        if (isRunning) return@withContext
        isRunning = true
        try {
            serverSocket = ServerSocket(port)
            Log.i("TcpServer", "Server started on port $port")
            while (isRunning) {
                val client = serverSocket?.accept() ?: break
                Log.i("TcpServer", "Client connected: ${client.inetAddress.hostAddress}")
                scope.launch {
                    handleClient(client)
                }
            }
        } catch (e: Exception) {
            if (isRunning) Log.e("TcpServer", "Server error", e)
        } finally {
            stop()
        }
    }

    private suspend fun handleClient(client: Socket) = withContext(Dispatchers.IO) {
        var writer: PrintWriter? = null
        try {
            val reader = BufferedReader(InputStreamReader(client.getInputStream()))
            writer = PrintWriter(client.getOutputStream(), true)
            clientWriters.add(writer)
            
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
            if (isRunning) Log.e("TcpServer", "Client handling error", e)
        } finally {
            writer?.let { clientWriters.remove(it) }
            try {
                client.close()
            } catch (e: Exception) {
                // Ignore
            }
            Log.i("TcpServer", "Client disconnected")
        }
    }

    fun broadcast(msg: String) {
        scope.launch {
            val writers = synchronized(clientWriters) { clientWriters.toList() }
            writers.forEach { it.println(msg) }
        }
    }

    fun stop() {
        if (!isRunning) return
        isRunning = false
        try {
            serverSocket?.close()
        } catch (e: Exception) {
            // Ignore
        }
        serverSocket = null
        scope.cancel()
        // Re-create scope in case it's started again
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        clientWriters.clear()
    }
}
