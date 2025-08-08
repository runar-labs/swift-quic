import XCTest
import Foundation
import NIOCore
import NIOPosix
import NIOSSL
@testable import Quic

final class QuinnInteropTests: XCTestCase {
    private func requireEnvEnabled() throws {
        guard ProcessInfo.processInfo.environment["RUN_QUINN_INTEROP"] == "1" else {
            throw XCTSkip("Quinn interop tests are skipped by default; set RUN_QUINN_INTEROP=1 to run.")
        }
    }

    private func lookupEnv(_ key: String) throws -> String {
        guard let value = ProcessInfo.processInfo.environment[key], value.isEmpty == false else {
            throw XCTSkip("Missing env \(key); skipping Quinn interop test")
        }
        return value
    }

    private func runProcess(_ path: String, args: [String]) throws -> (status: Int32, stdout: String, stderr: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args

        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        try proc.run()
        proc.waitUntilExit()

        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        return (proc.terminationStatus, String(decoding: outData, as: UTF8.self), String(decoding: errData, as: UTF8.self))
    }

    func testQuinnBinariesPresent() throws {
        try requireEnvEnabled()
        let serverBin = try lookupEnv("QUINN_SERVER_BIN")
        let clientBin = try lookupEnv("QUINN_CLIENT_BIN")

        // Smoke: both binaries respond to --help
        let s = try runProcess(serverBin, args: ["--help"])
        XCTAssertEqual(s.status, 0)
        XCTAssertFalse(s.stdout.isEmpty || s.stderr.contains("No such file"))

        let c = try runProcess(clientBin, args: ["--help"])
        XCTAssertEqual(c.status, 0)
        XCTAssertFalse(c.stdout.isEmpty || c.stderr.contains("No such file"))
    }

    func testQuinnEchoInteropSkeleton() throws {
        try requireEnvEnabled()
        let serverAddr = ProcessInfo.processInfo.environment["QUINN_SERVER_ADDR"] ?? "127.0.0.1:4433"

        // Set up a UDP channel with our QUIC client pipeline, attempt to connect to Quinn server.
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }

        let parts = serverAddr.split(separator: ":")
        XCTAssertEqual(parts.count, 2, "QUINN_SERVER_ADDR must be host:port")
        let host = String(parts[0])
        let port = Int(parts[1]) ?? 4433

        var clientTLS = TLSConfiguration.makeClientConfiguration()
        clientTLS.minimumTLSVersion = .tlsv13
        clientTLS.maximumTLSVersion = .tlsv13
        clientTLS.applicationProtocols = ["echo"]
        clientTLS.certificateVerification = .none
        let clientContext = try NIOSSLContext(configuration: clientTLS)

        let bootstrap = DatagramBootstrap(group: group)
            .channelInitializer { channel in
                let remote = try! SocketAddress.makeAddressResolvingHost(host, port: port)
                let handler = try! QUICClientHandler(remote, version: .version1, tlsContext: clientContext)
                return channel.pipeline.addHandlers([
                    QuicConnectionMultiplexer(channel: channel, tlsContext: clientContext, inboundConnectionInitializer: nil),
                    handler
                ])
            }

        let channel = try bootstrap.bind(host: "0.0.0.0", port: 0).wait()
        defer { try? channel.close().wait() }

        // Trigger connect to remote by sending an initial write (client handler does on active)
        // Drive event loop for a short time and assert no crash; full echo left for future when server is pinned.
        let deadline = NIODeadline.now() + .seconds(2)
        while group.next().inEventLoop == false && NIODeadline.now() < deadline { }

        throw XCTSkip("End-to-end echo assertion pending Quinn server fixture; smoke bind/init ok.")
    }
}


