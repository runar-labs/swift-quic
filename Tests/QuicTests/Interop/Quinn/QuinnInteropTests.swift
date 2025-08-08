import XCTest
import Foundation

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
        _ = try lookupEnv("QUINN_SERVER_BIN")
        _ = try lookupEnv("QUINN_CLIENT_BIN")
        throw XCTSkip("Interop handshake+echo wiring TBD: will spin Quinn server and connect via SwiftNIO datagram + QUIC handlers.")
    }
}


