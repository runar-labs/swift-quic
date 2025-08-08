import XCTest
import NIOCore
import NIOEmbedded
@testable import Quic

final class AckInjectionTests: XCTestCase {
    final class CaptureOutboundHandler: ChannelOutboundHandler {
        typealias OutboundIn = [any Packet]
        var captured: [[any Packet]] = []
        func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
            let pkts = self.unwrapOutboundIn(data)
            captured.append(pkts)
            context.write(data, promise: promise)
        }
    }

    func testAckInjectedIntoEmptyInitial() throws {
        let channel = EmbeddedChannel()
        let ack = ACKChannelHandler()
        let cap = CaptureOutboundHandler()
        try channel.pipeline.addHandlers([ack, cap]).wait()

        // Simulate receiving an Initial numbered packet to trigger ACK need
        let header = InitialHeader(version: .version1, destinationID: ConnectionID(randomOfLength: 8), sourceID: ConnectionID(randomOfLength: 8))
        let inPkt = InitialPacket(header: header, payload: [Frames.Ping()])
        try channel.writeInbound(inPkt)

        // Write an empty Initial packet outbound; ACK handler should inject an ACK frame
        let outHeader = InitialHeader(version: .version1, destinationID: header.sourceID, sourceID: header.destinationID)
        let outPkt = InitialPacket(header: outHeader, payload: [])
        try channel.writeOutbound([outPkt] as [any Packet])
        try channel.finish()

        // Verify captured outbound has an ACK frame injected
        let all = cap.captured.flatMap { $0 }
        guard let first = all.first as? InitialPacket else { return XCTFail("missing outbound initial packet") }
        XCTAssertTrue(first.payload.contains { $0 as? Frames.ACK != nil })
    }
}


