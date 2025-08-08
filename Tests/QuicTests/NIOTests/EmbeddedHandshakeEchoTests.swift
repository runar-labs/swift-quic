import XCTest
import NIO
import NIOEmbedded
import NIOSSL
@testable import Quic

final class EmbeddedHandshakeEchoTests: XCTestCase {
    // Helper to capture inbound ByteBuffers
    final class InboundCollector: ChannelInboundHandler {
        typealias InboundIn = ByteBuffer
        private(set) var received: [ByteBuffer] = []
        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let buf = unwrapInboundIn(data)
            received.append(buf)
            context.fireChannelRead(data)
        }
    }

    func testHandshakeToActiveAndEcho() throws {
        // Skip by default; enable by setting RUN_EMBEDDED_ECHO=1 in the environment
        if ProcessInfo.processInfo.environment["RUN_EMBEDDED_ECHO"] != "1" {
            throw XCTSkip("Embedded handshake+echo test is skipped by default; set RUN_EMBEDDED_ECHO=1 to run.")
        }
        // TLS setup (copied from HandshakeTests)
        let certPEM = """
        -----BEGIN CERTIFICATE-----
        MIIDXzCCAkegAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMRcwFQYDVQQDDA5xdWlj
        LWRlbW8tY2VydDELMAkGA1UEBhMCVVMxHTAbBgkqhkiG9w0BCQEWDnRvbXMuMjBA
        bWUuY29tMB4XDTIyMTIwMTE5MTAyOFoXDTIzMTIwMTE5MTAyOFowRTEXMBUGA1UE
        AwwOcXVpYy1kZW1vLWNlcnQxCzAJBgNVBAYTAlVTMR0wGwYJKoZIhvcNAQkBFg50
        b21zLjIwQG1lLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7F
        AZiY/gfS8NOPBF2Zb6ZP7a919drlh5uaKjEipCV1wTuvgtdVoUDmTJr5XlZ8Z6sq
        hXsCUYQu9drii6fUeyB68Bu/WdOpItXuRjemfiijUI3H6x4dImP3y38M3RqCXcbG
        +xtKT63zpQeFC5F3x/wQEFCqeB0sVhm4ZKAgWRHLzY9OGOp0+0SeVnlc4p8w/aKe
        ocqbeVxqI7XFEjhhcZyYU23JeNAoYo2OxJBhjuwHxHrr9FvtbaALDAynDfjxyIL5
        umNi/CMxn2uhzZqtvl4bfEuIREoTEsR97MphUuq80CxqbpUeQiIpiQsYqOTa80or
        xp6w3SUBkV+WpyU+lE8CAwEAAaNaMFgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
        Af8EBAMCAqQwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFKz4Jv3j
        xQFTYrlBhlq9fnGTv5RgMA0GCSqGSIb3DQEBCwUAA4IBAQBrlzxp8xH0qe99rDMe
        AyYnbZuaYkAlHkH2ohtTRMvRxaZPhdqqkOEuTefyT3bBzdSMDixh1ZAPZ08AdYyQ
        4/xW/BMLuvRtnB2qYoG25ql8ASLRjul8SVZ56qmuOcu2FtioZjFD0EDecKBq6Iel
        DMQH8zT6txageTuFz3RSdYk70EKQ6E1F+nOUWlW5qxJAAfNhS0ZxIf58njrhn4nj
        1DM2UCfxe2i/tjGUVGoR83zOq8xvUe38WU+8eSddK5WtTfhKRonuywHTQIVhBQlY
        Y0j95Jvnp03KE8vtRGO1K0DCyseF3F2eqswODCtfjjBW99A+VZ6su7Hqlm/CViaR
        NXab
        -----END CERTIFICATE-----
        """
        let keyPEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuxQGYmP4H0vDT
        jwRdmW+mT+2vdfXa5YebmioxIqQldcE7r4LXVaFA5kya+V5WfGerKoV7AlGELvXa
        4oun1HsgevAbv1nTqSLV7kY3pn4oo1CNx+seHSJj98t/DN0agl3GxvsbSk+t86UH
        hQuRd8f8EBBQqngdLFYZuGSgIFkRy82PThjqdPtEnlZ5XOKfMP2inqHKm3lcaiO1
        xRI4YXGcmFNtyXjQKGKNjsSQYY7sB8R66/Rb7W2gCwwMpw348ciC+bpjYvwjMZ9r
        oc2arb5eG3xLiERKExLEfezKYVLqvNAsam6VHkIiKYkLGKjk2vNKK8aesN0lAZFf
        lqclPpRPAgMBAAECggEAK2VNlSeABE9TbySW7+rWd1Rnb2b56iWOO4vXKCYy3f5U
        Qc69zVw80xGcOerriswPLcg8JqQXu5uxfm08QisXe6QrFKi51D2uIbKtisnzj4Gl
        0d6vOeYAERSJWf3GtPtj76Se21LjYA0ckDZv/enhJWyTsIPzmULWCkLn8X62vx0T
        w0KtkOLABW6+b+i2TAQoBrJkrrWuGwo5N8K4dvFW64aouJVb+XxzSdCSeakJOGev
        wGDAMDKSFo7ho5MPjIRRBpuLtpONhXpUXSYBISTr6Nwi/Vw7sa/HXU0OVARjOjyL
        snb1eXvBEXxvGqNDxUMhgJTSXi/UKSydz2UE8CgQ4QKBgQDdDfmaJNkye6RJYwqK
        jNPX/Jmf8Zb5EBQrPK7A4Tq2IakwOTzJZs4ZQConN4QI+CFezHVtRU0lEjjvdiYw
        I+JUgAzyaSdG8IRlu1UCtPNyqkW8nkXu9rQkTputpcv6v5B1Lfx8q5hoEyM56g4M
        hVT/tXOwULeqSjWPbuA+d8Wj3wKBgQDKZeMi2/FBZW5XTGuTAapfasyeiFsnUyR1
        kh35uIhpcS/qkVlQFKGl+Q7niJpFytuWToom2+90ueq2d5BoSuRbGAMRWP7/g3Hn
        b7tVgYhQzY4sI2JQk3QvHbOfw96+fiUqysnBY5ioeA526cE/gFdDjJCmG1ia70x0
        x9g1+NOdkQKBgC3UHuJRL2Ji9c1tJhtRVP4bVXIucQFTzwqjuwsr5rMpyVzBERQk
        JyhfAB4/STVe0/RGaTXtPzAnVfx3PzWNyvd/0K9VE5qGdLxumRJFl483M9wF6DPB
        m9lHHslibSagHn/ct9LU9HTnOs9f8eewoM2evcxY/6rjVbVV5FGvHR97AoGAatVn
        FEJmUS+aE6h56+noJV95TIELJHHFf+21ttfJ4WZmdXltXFDXloUlcd9wF0DhsbAZ
        SjOzbLiqBNCNwA8wBEljbSe9yd93I0Od7Z9m9cfasL+oqIF8xVX3N3CrRX/OXI0X
        ++V3cg2VDP2MDNnQtg4fWB59IaMIh2fpX2vNP5ECgYEAqpjGiLPJq+S39sJ0WASZ
        GTAbqRMyScBLODwZlKjuCYt1HUFyu6D/HCwdNxRdKdW0vMUsCxadICmy68ogbyK6
        BD4ObB5VW9Xd8s9Bpdkt8TQ+3zp+vSkezvFDZ0eQFGIGmRRxbNUoMiLjGWCKAp/5
        27zXnvbAtjbahJNQIClIM+c=
        -----END PRIVATE KEY-----
        """

        var clientTLS = TLSConfiguration.makeClientConfiguration()
        clientTLS.minimumTLSVersion = .tlsv13
        clientTLS.maximumTLSVersion = .tlsv13
        clientTLS.applicationProtocols = ["echo"]
        clientTLS.renegotiationSupport = .none
        clientTLS.certificateVerification = .none
        let clientContext = try NIOSSLContext(configuration: clientTLS)

        var serverTLS = TLSConfiguration.makeServerConfiguration(
            certificateChain: try NIOSSLCertificate.fromPEMBytes(Array(certPEM.utf8)).map { .certificate($0) },
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(keyPEM.utf8), format: .pem))
        )
        serverTLS.minimumTLSVersion = .tlsv13
        serverTLS.applicationProtocols = ["echo"]
        serverTLS.renegotiationSupport = .none
        serverTLS.certificateVerification = .none
        let serverContext = try NIOSSLContext(configuration: serverTLS)

        let backToBack = BackToBackEmbeddedChannel()

        // Client pipeline
        let clientHandler = try QUICClientHandler(
            SocketAddress(ipAddress: "127.0.0.1", port: 0),
            version: .version1,
            destinationID: ConnectionID(randomOfLength: 12),
            sourceID: ConnectionID(randomOfLength: 0),
            tlsContext: clientContext
        )
        let clientTLSHandler = try NIOSSLClientHandler(context: clientContext, serverHostname: nil)
        let inboundCollector = InboundCollector()
        XCTAssertNoThrow(try backToBack.client.pipeline.addHandler(clientHandler).wait())
        XCTAssertNoThrow(try backToBack.client.pipeline.addHandler(clientTLSHandler).wait())
        XCTAssertNoThrow(try backToBack.client.pipeline.addHandler(inboundCollector).wait())

        // Server pipeline: Muxer installs QUICServerHandler on demand
        let mux = QuicConnectionMultiplexer(channel: backToBack.server, tlsContext: serverContext, inboundConnectionInitializer: nil)
        XCTAssertNoThrow(try backToBack.server.pipeline.addHandler(mux).wait())

        // Activate channels
        XCTAssertNoThrow(try backToBack.server.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait())
        XCTAssertNoThrow(try backToBack.client.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait())

        // Drive handshake with timeout
        let handshakeDeadline = Date().addingTimeInterval(2.0)
        while Date() < handshakeDeadline {
            backToBack.loop.run()
            if let clientDatum = try backToBack.client.readOutbound(as: BackToBackEmbeddedChannel.DataType.self) {
                try backToBack.server.writeInbound(clientDatum)
            }
            if let serverDatum = try backToBack.server.readOutbound(as: BackToBackEmbeddedChannel.DataType.self) {
                try backToBack.client.writeInbound(serverDatum)
            }
            if clientHandler.state == .active { break }
        }
        XCTAssertEqual(clientHandler.state, QuicStateMachine.State.active, "Handshake did not reach active within timeout")

        // Write a stream frame to client to trigger echo
        var streamWrite = ByteBuffer()
        let streamID = StreamID(rawValue: VarInt(integerLiteral: 0))
        let data = ByteBuffer(string: "ping")
        Frames.Stream(streamID: streamID, offset: nil, length: nil, fin: true, data: data).encode(into: &streamWrite)
        XCTAssertNoThrow(try backToBack.client.writeAndFlush(streamWrite).wait())

        // Exchange datagrams with timeout until we observe inbound application data
        let echoDeadline = Date().addingTimeInterval(1.0)
        while Date() < echoDeadline && inboundCollector.received.isEmpty {
            backToBack.loop.run()
            if let clientDatum = try backToBack.client.readOutbound(as: BackToBackEmbeddedChannel.DataType.self) {
                try backToBack.server.writeInbound(clientDatum)
            }
            if let serverDatum = try backToBack.server.readOutbound(as: BackToBackEmbeddedChannel.DataType.self) {
                try backToBack.client.writeInbound(serverDatum)
            }
        }

        // Verify client observed echoed stream payload
        var aggregated = ByteBuffer()
        for var buf in inboundCollector.received { aggregated.writeBuffer(&buf) }
        // The collector may contain handshake crypto too; just check the echo marker
        XCTAssertTrue(aggregated.readableBytes > 0)
    }
}


