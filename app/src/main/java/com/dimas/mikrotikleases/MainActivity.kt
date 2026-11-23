package com.dimas.mikrotikleases

import android.content.SharedPreferences
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Credentials
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.*
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

// ---------- Model & Settings ----------
data class Lease(
    val address: String, val mac: String, val host: String,
    val server: String, val status: String, val expires: String
)

data class Settings(
    val host: String = "192.168.100.2",
    val webPort: String = "7721",
    val apiPort: String = "8777",
    val user: String = "admin",
    val pass: String = "",
    val https: Boolean = false,
    val listName: String = "___Inet-Akses___"
)

private fun SharedPreferences.loadSettings(): Settings {
    val d = Settings()
    return Settings(
        getString("host", d.host)!!, getString("webPort", d.webPort)!!,
        getString("apiPort", d.apiPort)!!, getString("user", d.user)!!,
        getString("pass", d.pass)!!, getBoolean("https", d.https), getString("listName", d.listName)!!
    )
}

private fun SharedPreferences.saveSettings(s: Settings) = edit()
    .putString("host", s.host).putString("webPort", s.webPort).putString("apiPort", s.apiPort)
    .putString("user", s.user).putString("pass", s.pass).putBoolean("https", s.https).putString("listName", s.listName).apply()

// ---------- REST API (RouterOS v7, lewat port web) ----------
private val client: OkHttpClient by lazy {
    // Terima sertifikat self-signed MikroTik (hanya dipakai jika HTTPS aktif, untuk jaringan lokal)
    val trust = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
        override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
        override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
    }
    val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), SecureRandom()) }
    OkHttpClient.Builder()
        .sslSocketFactory(ssl.socketFactory, trust)
        .hostnameVerifier { _, _ -> true }
        .connectTimeout(6, TimeUnit.SECONDS).readTimeout(8, TimeUnit.SECONDS).build()
}

private fun fetchRest(s: Settings): List<Lease> {
    val scheme = if (s.https) "https" else "http"
    val req = Request.Builder()
        .url("$scheme://${s.host}:${s.webPort}/rest/ip/dhcp-server/lease?dynamic=true")
        .header("Authorization", Credentials.basic(s.user, s.pass)).build()
    client.newCall(req).execute().use { r ->
        if (!r.isSuccessful) error("HTTP ${r.code}")
        val arr = JSONArray(r.body?.string() ?: "[]")
        return List(arr.length()) {
            val o = arr.getJSONObject(it)
            Lease(
                o.optString("address", "-"), o.optString("mac-address", "-"),
                o.optString("host-name", "-"), o.optString("server", "-"),
                o.optString("status", "-"), o.optString("expires-after", "-")
            )
        }
    }
}

// ---------- API biner RouterOS (v6 & v7, lewat port API) ----------
private fun writeWord(o: OutputStream, w: String) {
    val b = w.toByteArray(Charsets.UTF_8)
    val l = b.size
    when {
        l < 0x80 -> o.write(l)
        l < 0x4000 -> { val v = l or 0x8000; o.write(v shr 8); o.write(v) }
        l < 0x200000 -> { val v = l or 0xC00000; o.write(v shr 16); o.write(v shr 8); o.write(v) }
        else -> { val v = l or 0xE0000000.toInt(); o.write(v ushr 24); o.write(v ushr 16); o.write(v ushr 8); o.write(v) }
    }
    o.write(b)
}

private fun sendSentence(o: OutputStream, vararg words: String) {
    words.forEach { writeWord(o, it) }
    o.write(0); o.flush()
}

private fun readWord(i: DataInputStream): String {
    val b = i.readUnsignedByte()
    val len = when {
        b < 0x80 -> b
        b < 0xC0 -> ((b and 0x3F) shl 8) or i.readUnsignedByte()
        b < 0xE0 -> { val x = i.readUnsignedByte(); ((b and 0x1F) shl 16) or (x shl 8) or i.readUnsignedByte() }
        b < 0xF0 -> {
            val x = i.readUnsignedByte(); val y = i.readUnsignedByte()
            ((b and 0x0F) shl 24) or (x shl 16) or (y shl 8) or i.readUnsignedByte()
        }
        else -> i.readInt()
    }
    if (len == 0) return ""
    val buf = ByteArray(len); i.readFully(buf)
    return String(buf, Charsets.UTF_8)
}

private fun readSentence(i: DataInputStream): List<String> {
    val words = mutableListOf<String>()
    while (true) { val w = readWord(i); if (w.isEmpty()) return words; words += w }
}

// Baca semua sentence sampai !done / !fatal. Melempar error jika ada !trap.
private fun readReply(i: DataInputStream): List<Map<String, String>> {
    val rows = mutableListOf<Map<String, String>>()
    while (true) {
        val sent = readSentence(i)
        if (sent.isEmpty()) continue
        val attrs = sent.drop(1).filter { it.startsWith("=") }.associate {
            val p = it.indexOf('=', 1); it.substring(1, p) to it.substring(p + 1)
        }
        when (sent[0]) {
            "!re" -> rows += attrs
            "!done" -> return rows
            "!trap", "!fatal" -> error(attrs["message"] ?: sent[0])
        }
    }
}

private fun fetchApi(s: Settings): List<Lease> {
    Socket().use { sock ->
        sock.connect(InetSocketAddress(s.host, s.apiPort.toInt()), 6000)
        sock.soTimeout = 8000
        val inp = DataInputStream(BufferedInputStream(sock.getInputStream()))
        val out = BufferedOutputStream(sock.getOutputStream())
        sendSentence(out, "/login", "=name=${s.user}", "=password=${s.pass}")
        readReply(inp)
        sendSentence(out, "/ip/dhcp-server/lease/print", "?dynamic=true")
        return readReply(inp).map {
            Lease(
                it["address"] ?: "-", it["mac-address"] ?: "-", it["host-name"] ?: "-",
                it["server"] ?: "-", it["status"] ?: "-", it["expires-after"] ?: "-"
            )
        }
    }
}

// ---------- Tambah ke Firewall Address List ----------
private fun addRest(s: Settings, address: String, comment: String) {
    val scheme = if (s.https) "https" else "http"
    val body = JSONObject().put("list", s.listName).put("address", address)
    if (comment.isNotBlank()) body.put("comment", comment)
    val json = body.toString()
    val req = Request.Builder()
        .url("$scheme://${s.host}:${s.webPort}/rest/ip/firewall/address-list")
        .header("Authorization", Credentials.basic(s.user, s.pass))
        .put(json.toRequestBody("application/json".toMediaType())).build()
    client.newCall(req).execute().use { r ->
        if (!r.isSuccessful) {
            val detail = try { JSONObject(r.body?.string() ?: "").optString("detail") } catch (e: Exception) { "" }
            error(if (detail.isNotEmpty()) detail else "HTTP ${r.code}")
        }
    }
}

private fun addApi(s: Settings, address: String, comment: String) {
    Socket().use { sock ->
        sock.connect(InetSocketAddress(s.host, s.apiPort.toInt()), 6000)
        sock.soTimeout = 8000
        val inp = DataInputStream(BufferedInputStream(sock.getInputStream()))
        val out = BufferedOutputStream(sock.getOutputStream())
        sendSentence(out, "/login", "=name=${s.user}", "=password=${s.pass}")
        readReply(inp)
        val words = mutableListOf("/ip/firewall/address-list/add", "=list=${s.listName}", "=address=$address")
        if (comment.isNotBlank()) words += "=comment=$comment"
        sendSentence(out, *words.toTypedArray())
        readReply(inp)
    }
}

// Coba REST (port web) dulu, jika gagal pakai API (port API).
private fun fetchLeases(s: Settings): Pair<List<Lease>, String> {
    return try {
        fetchRest(s) to "REST (port ${s.webPort})"
    } catch (e1: Exception) {
        try {
            fetchApi(s) to "API (port ${s.apiPort})"
        } catch (e2: Exception) {
            error("Web: ${e1.message}\nAPI: ${e2.message}")
        }
    }
}

// ---------- UI ----------
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { Surface(Modifier.fillMaxSize()) { App() } } }
    }
}

@Composable
fun App() {
    val prefs = LocalContext.current.getSharedPreferences("cfg", 0)
    var settings by remember { mutableStateOf(prefs.loadSettings()) }
    var showSettings by remember { mutableStateOf(false) }

    if (showSettings) {
        BackHandler { showSettings = false }
        SettingsScreen(settings) { settings = it; prefs.saveSettings(it); showSettings = false }
    } else {
        LeasesScreen(settings) { showSettings = true }
    }
}

@Composable
fun SettingsScreen(initial: Settings, onSave: (Settings) -> Unit) {
    var s by remember { mutableStateOf(initial) }
    val num = KeyboardOptions(keyboardType = KeyboardType.Number)
    Column(Modifier.statusBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Pengaturan", style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(s.host, { s = s.copy(host = it.trim()) }, label = { Text("IP MikroTik") },
            singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(s.webPort, { s = s.copy(webPort = it.filter(Char::isDigit)) }, label = { Text("Port Web") },
            singleLine = true, keyboardOptions = num, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(s.apiPort, { s = s.copy(apiPort = it.filter(Char::isDigit)) }, label = { Text("Port API") },
            singleLine = true, keyboardOptions = num, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(s.listName, { s = s.copy(listName = it.trim()) }, label = { Text("Nama Address List") },
            singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(s.user, { s = s.copy(user = it) }, label = { Text("Username") },
            singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(s.pass, { s = s.copy(pass = it) }, label = { Text("Password") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(s.https, { s = s.copy(https = it) }); Spacer(Modifier.width(8.dp)); Text("Web pakai HTTPS (www-ssl)")
        }
        Button(onClick = { onSave(s) }, modifier = Modifier.fillMaxWidth()) { Text("Simpan") }
    }
}

@Composable
fun LeasesScreen(settings: Settings, onOpenSettings: () -> Unit) {
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var source by remember { mutableStateOf<String?>(null) }
    var leases by remember { mutableStateOf<List<Lease>>(emptyList()) }
    var confirm by remember { mutableStateOf<Lease?>(null) }
    var comment by remember { mutableStateOf("") }
    var notice by remember { mutableStateOf<Pair<String, Boolean>?>(null) }

    fun load() {
        loading = true; error = null; notice = null
        scope.launch {
            try {
                val (data, src) = withContext(Dispatchers.IO) { fetchLeases(settings) }
                leases = data; source = src
            } catch (e: Exception) { error = e.message; leases = emptyList(); source = null }
            loading = false
        }
    }

    fun addToList(l: Lease, comment: String) {
        val viaRest = source?.startsWith("REST") == true
        scope.launch {
            notice = try {
                withContext(Dispatchers.IO) {
                    if (viaRest) addRest(settings, l.address, comment.trim()) else addApi(settings, l.address, comment.trim())
                }
                "${l.address} ditambahkan ke ${settings.listName}" to true
            } catch (e: Exception) {
                "Gagal menambahkan ${l.address}: ${e.message}" to false
            }
        }
    }

    confirm?.let { l ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text("Tambah ke address list") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Tambahkan ${l.address} ke list ${settings.listName}?")
                    OutlinedTextField(comment, { comment = it }, label = { Text("Comment (opsional)") },
                        singleLine = true, modifier = Modifier.fillMaxWidth())
                }
            },
            confirmButton = { TextButton(onClick = { confirm = null; addToList(l, comment) }) { Text("Tambahkan") } },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Batal") } }
        )
    }

    Column(Modifier.statusBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("DHCP Leases (Dynamic)", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            TextButton(onClick = onOpenSettings) { Text("Pengaturan") }
        }
        Text("Router: ${settings.host}", style = MaterialTheme.typography.bodySmall)
        Button(onClick = { load() }, enabled = !loading, modifier = Modifier.fillMaxWidth()) {
            Text(if (loading) "Memuat..." else "Ambil Data")
        }
        error?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
        notice?.let { (msg, ok) ->
            Text(msg, color = if (ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        }
        source?.let { Text("Sumber: $it  •  Total: ${leases.size} lease") }

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(leases) { l ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp)) {
                        Text(l.address, style = MaterialTheme.typography.titleMedium)
                        Text("Host: ${l.host}")
                        Text("MAC: ${l.mac}")
                        Text("Server: ${l.server}  •  Status: ${l.status} (D)")
                        Text("Expires: ${l.expires}")
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = { comment = if (l.host != "-") l.host else ""; confirm = l }, modifier = Modifier.fillMaxWidth()) {
                            Text("Tambah ke ${settings.listName}")
                        }
                    }
                }
            }
        }
    }
}
