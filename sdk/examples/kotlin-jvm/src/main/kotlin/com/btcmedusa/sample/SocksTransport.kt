// A PerseverusTransport in plain Kotlin: the shape a wallet's own Tor client
// plugs into. Use it with `MEDUSA_TRANSPORT=custom`.
//
// It sends each request over a Tor SOCKS proxy and gets the isolation the SDK
// asks for the standard way: Tor puts streams with different SOCKS
// username/password pairs on different circuits (IsolateSOCKSAuth, on by
// default), so the username is the request's circuit tag.
//
// A wallet with its own Tor client replaces `openTorStream` with that
// client's "open a stream to host:port on the circuit for <tag>" call. The
// rest (HTTP/1.1 over the stream, TLS for https://) stays the same.

package com.btcmedusa.sample

import com.btcmedusa.perseverus.Header
import com.btcmedusa.perseverus.PerseverusTransport
import com.btcmedusa.perseverus.TransportException
import com.btcmedusa.perseverus.TransportRequest
import com.btcmedusa.perseverus.TransportResponse
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class SocksTorTransport(private val socksHost: String, private val socksPort: Int) : PerseverusTransport {

    override fun send(request: TransportRequest): TransportResponse {
        val uri = URI(request.url)
        val https = uri.scheme == "https"
        val host = uri.host
        val port = if (uri.port != -1) uri.port else if (https) 443 else 80
        val timeout = if (request.timeoutMs > 0uL) request.timeoutMs.toLong().coerceAtMost(Int.MAX_VALUE.toLong()).toInt() else 180_000
        try {
            openTorStream(host, port, circuit = request.circuit, timeoutMs = timeout).use { tor ->
                val socket: Socket = if (https) {
                    // TLS inside the Tor stream: the exit relay sees only ciphertext.
                    (SSLSocketFactory.getDefault() as SSLSocketFactory)
                        .createSocket(tor, host, port, true).also { (it as SSLSocket).startHandshake() }
                } else tor
                socket.use { return http11(it, request, uri, host) }
            }
        } catch (e: TransportException) {
            throw e
        } catch (e: Exception) {
            // No response arrived: tell the SDK so (it reports a Network error).
            throw TransportException.Failed("${e::class.simpleName}: ${e.message}")
        }
    }

    /** A TCP stream to host:port through Tor, on the circuit for `circuit`.
     *  SOCKS5 with username/password auth; the hostname is resolved by Tor. */
    private fun openTorStream(host: String, port: Int, circuit: String, timeoutMs: Int): Socket {
        val s = Socket()
        s.soTimeout = timeoutMs
        s.connect(InetSocketAddress(socksHost, socksPort), timeoutMs)
        val out = s.getOutputStream()
        val inp = DataInputStream(s.getInputStream())
        out.write(byteArrayOf(5, 1, 2)) // SOCKS5, one method: username/password
        val method = ByteArray(2).also { inp.readFully(it) }
        if (method[0] != 5.toByte() || method[1] != 2.toByte()) throw TransportException.Failed("SOCKS proxy refused username/password auth")
        val user = circuit.toByteArray()
        val pass = "x".toByteArray()
        out.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass)
        val auth = ByteArray(2).also { inp.readFully(it) }
        if (auth[1] != 0.toByte()) throw TransportException.Failed("SOCKS auth failed")
        val h = host.toByteArray()
        out.write(byteArrayOf(5, 1, 0, 3, h.size.toByte()) + h + byteArrayOf((port shr 8).toByte(), port.toByte()))
        val head = ByteArray(4).also { inp.readFully(it) }
        if (head[1] != 0.toByte()) throw TransportException.Failed("Tor couldn't connect to $host:$port (SOCKS reply ${head[1]})")
        when (head[3].toInt()) { // skip the bound address
            1 -> inp.readFully(ByteArray(4 + 2))
            4 -> inp.readFully(ByteArray(16 + 2))
            3 -> inp.readFully(ByteArray(inp.readUnsignedByte() + 2))
        }
        return s
    }

    /** One HTTP/1.1 request on `socket`, `Connection: close`. */
    private fun http11(socket: Socket, r: TransportRequest, uri: URI, host: String): TransportResponse {
        val path = (uri.rawPath.ifEmpty { "/" }) + (uri.rawQuery?.let { "?$it" } ?: "")
        val head = StringBuilder("${r.method} $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\nUser-Agent: perseverus-sample\r\n")
        for (h in r.headers) head.append("${h.name}: ${h.value}\r\n")
        if (r.method == "POST" || r.body.isNotEmpty()) head.append("Content-Length: ${r.body.size}\r\n")
        head.append("\r\n")
        val out = socket.getOutputStream()
        out.write(head.toString().toByteArray())
        out.write(r.body)
        out.flush()

        val inp = socket.getInputStream().buffered()
        val statusLine = readLine(inp) ?: throw TransportException.Failed("connection closed before a response")
        val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: throw TransportException.Failed("bad status line: $statusLine")
        val headers = mutableListOf<Header>()
        while (true) {
            val line = readLine(inp) ?: break
            if (line.isEmpty()) break
            val i = line.indexOf(':')
            if (i > 0) headers += Header(line.substring(0, i).trim(), line.substring(i + 1).trim())
        }
        fun header(n: String) = headers.firstOrNull { it.name.equals(n, ignoreCase = true) }?.value
        val body = when {
            header("Transfer-Encoding")?.contains("chunked", ignoreCase = true) == true -> readChunked(inp)
            header("Content-Length") != null -> ByteArray(header("Content-Length")!!.toInt()).also { DataInputStream(inp).readFully(it) }
            else -> inp.readBytes()
        }
        return TransportResponse(status = status.toUShort(), headers = headers, body = body)
    }

    private fun readLine(inp: InputStream): String? {
        val b = ByteArrayOutputStream()
        while (true) {
            val c = inp.read()
            if (c == -1) return if (b.size() == 0) null else b.toString(Charsets.ISO_8859_1)
            if (c == '\n'.code) return b.toString(Charsets.ISO_8859_1).trimEnd('\r')
            b.write(c)
        }
    }

    private fun readChunked(inp: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val data = DataInputStream(inp)
        while (true) {
            val size = (readLine(inp) ?: break).substringBefore(';').trim().toInt(16)
            if (size == 0) break
            out.write(ByteArray(size).also { data.readFully(it) })
            readLine(inp) // CRLF after each chunk
        }
        return out.toByteArray()
    }
}

/** Every circuit tag this transport has been handed, for `transport-check`. */
class RecordingTransport(private val inner: PerseverusTransport) : PerseverusTransport {
    val seen = java.util.Collections.synchronizedList(mutableListOf<Pair<String, String>>())
    override fun send(request: TransportRequest): TransportResponse {
        seen += request.circuit to "${request.method} ${URI(request.url).path}"
        return inner.send(request)
    }
}
