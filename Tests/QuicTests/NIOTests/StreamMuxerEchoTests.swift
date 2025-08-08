import XCTest
import NIOCore
import NIOEmbedded
@testable import Quic

final class StreamMuxerEchoTests: XCTestCase {
    func testEchoThroughMultiplexer() throws {
        // Setup embedded parent channel
        let loop = EmbeddedEventLoop()
        let parent = EmbeddedChannel(loop: loop)

        // Install muxer
        let mux = QuicStreamMultiplexer(channel: parent, inboundStreamInitializer: { channel in
            channel.pipeline.addHandler(StreamStateHandler())
        })
        try parent.pipeline.addHandler(mux).wait()

        // Simulate inbound stream frame (server side echo path)
        var payload = ByteBuffer(string: "echo")
        let frame = Frames.Stream(streamID: StreamID(rawValue: VarInt(integerLiteral: 0)), offset: nil, length: nil, fin: false, data: payload)
        var encoded = ByteBuffer()
        frame.encode(into: &encoded)

        try parent.writeInbound(encoded)
        parent.pipeline.fireChannelReadComplete()

        // Write outbound on child through muxer
        // The muxer opened a child channel lazily during read; simulate a write back by invoking child write API
        mux.childChannelWrite(Frames.Stream(streamID: frame.streamID, offset: nil, length: nil, fin: true, data: ByteBuffer(string: "echo")), promise: parent.eventLoop.makePromise())
        mux.childChannelFlush()

        // Read outbound buffer from parent
        var out: ByteBuffer? = try parent.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(out)
        // It should decode back to a stream frame
        if var buf = out {
            let decoded = buf.readStreamFrame()
            XCTAssertNotNil(decoded)
            XCTAssertEqual(decoded?.streamID, frame.streamID)
            XCTAssertEqual(decoded?.data.getString(at: 0, length: decoded?.data.readableBytes ?? 0), "echo")
        }

        _ = try parent.finish()
    }
}


