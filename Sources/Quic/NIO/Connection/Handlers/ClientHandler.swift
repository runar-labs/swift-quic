//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftQUIC open source project
//
// Copyright (c) 2023 the SwiftQUIC project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftQUIC project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import NIOSSL
import Logging

struct QuicStateMachine {
    enum HandshakeState: Equatable {
        case initial
        case firstHandshake
        case secondHandshake
        case done
    }

    enum State: Equatable {
        case idle
        case handshaking(HandshakeState)
        case active
        case receivedDisconnect
        case sentDisconnect
    }
}

final class QUICClientHandler: ChannelDuplexHandler, NIOSSLQuicDelegate {
    // typealias changes to wrap out ByteBuffer in an AddressedEvelope which describes where the packages are going
    public typealias InboundIn = Packet
    public typealias InboundOut = ByteBuffer
    public typealias OutboundOut = [any Packet]
    public typealias OutboundIn = ByteBuffer

    private let remoteAddress: SocketAddress
    private let ackHandler: ACKChannelHandler
    private let packetProtectorHandler: PacketProtectorHandler
    private let tlsHandler: NIOSSLClientHandler

    private(set) var state: QuicStateMachine.State {
        didSet { logger.debug("state transition", metadata: ["from": .string(String(describing: oldValue)), "to": .string(String(describing: self.state))]) }
    }

    let mode: EndpointRole = .client
    private let logger = Logger(label: "quic.client")
    let version: Quic.Version

    var retiredDCIDs: [ConnectionID] = []
    var dcid: Quic.ConnectionID {
        didSet {
            logger.debug("dcid updated", metadata: ["old": .string(oldValue.rawValue.hexString), "new": .string(self.dcid.rawValue.hexString)])
            self.retiredDCIDs.append(oldValue)
            // TODO: Do we need to update our PacketProtectorHandler
            // TODO: Do we need to update our Connection Muxer
        }
    }

    var retiredSCIDs: [ConnectionID] = []
    var scid: Quic.ConnectionID {
        didSet {
            logger.debug("scid updated", metadata: ["old": .string(oldValue.rawValue.hexString), "new": .string(self.scid.rawValue.hexString)])
            self.retiredSCIDs.append(oldValue)
            // TODO: Do we need to update our PacketProtectorHandler
            // TODO: Do we need to update our Connection Muxer
        }
    }

    private var storedContext: ChannelHandlerContext!

    // Quic Delegate Protocol Conformance
    private var transportParams: TransportParams
    var ourParams: [UInt8] {
        logger.trace("accessing client transport params")
        return (try? Array(self.transportParams.encode(perspective: .client).readableBytesView)) ?? []
    }

    var useLegacyQuicParams: Bool {
        self.version == .versionDraft29 ? true : false
    }

    func onReadSecret(epoch: UInt32, cipherSuite: UInt16, secret: [UInt8]) {
        guard let suite = try? CipherSuite(cipherSuite) else { logger.error("unsupported cipher suite", metadata: ["suite": .stringConvertible(cipherSuite)]); return }
        switch epoch {
            case 2: // Handshake
                self.packetProtectorHandler.installHandshakeKeys(secret: secret, for: .server, cipherSuite: suite)
            case 3: // Traffic / Application
                self.packetProtectorHandler.installTrafficKeys(secret: secret, for: .server, cipherSuite: suite)
            default:
                logger.error("unsupported epoch in onReadSecret", metadata: ["epoch": .stringConvertible(epoch)])
        }
    }

    func onWriteSecret(epoch: UInt32, cipherSuite: UInt16, secret: [UInt8]) {
        guard let suite = try? CipherSuite(cipherSuite) else { logger.error("unsupported cipher suite", metadata: ["suite": .stringConvertible(cipherSuite)]); return }
        switch epoch {
            case 2: // Handshake
                self.packetProtectorHandler.installHandshakeKeys(secret: secret, for: .client, cipherSuite: suite)
            case 3: // Traffic / Application
                self.packetProtectorHandler.installTrafficKeys(secret: secret, for: .client, cipherSuite: suite)
            default:
                logger.error("unsupported epoch in onWriteSecret", metadata: ["epoch": .stringConvertible(epoch)])
        }
    }

    func onPeerParams(params: [UInt8]) {
        logger.trace("peer transport params", metadata: ["params": .string(params.hexString)])
    }

    //var cumulativeCrypto:ByteBuffer = ByteBuffer()
    var partialCryptoBuffer: ByteBuffer = ByteBuffer()

    public init(_ remoteAddress: SocketAddress, version: Version, destinationID: ConnectionID? = nil, sourceID: ConnectionID? = nil, tlsContext: NIOSSLContext) {
        self.remoteAddress = remoteAddress
        self.version = version
        self.state = .idle
        self.transportParams = TransportParams.default

        // Initialize our Connection ID's
        self.dcid = destinationID ?? ConnectionID(randomOfLength: 12)
        self.scid = sourceID ?? ConnectionID(randomOfLength: 0)

        // Initialize our PacketProtectorHandler
        self.packetProtectorHandler = PacketProtectorHandler(initialDCID: self.dcid, scid: self.scid, version: version, perspective: .client, remoteAddress: remoteAddress)
        self.ackHandler = ACKChannelHandler()

        // Update the transport params with the original destination connection id
        self.transportParams.original_destination_connection_id = self.dcid
        self.transportParams.initial_source_connection_id = self.scid

        self.transportParams.max_idle_timeout = 30
        self.transportParams.stateless_reset_token = nil
        self.transportParams.max_udp_payload_size = 1_452
        //self.transportParams.initial_max_data = 786_432
        //self.transportParams.initial_max_stream_data_bidi_local = 524_288
        //self.transportParams.initial_max_stream_data_bidi_remote = 524_288
        //self.transportParams.initial_max_stream_data_uni = 524_288
        //self.transportParams.initial_max_streams_bidi = 100
        //self.transportParams.initial_max_streams_uni = 100
        //self.transportParams.ack_delay_exponent = 3
        //self.transportParams.max_ack_delay = 26
        //self.transportParams.disable_active_migration = true
        //self.transportParams.active_conn_id_limit = 4
        //self.transportParams.retry_source_connection_id = nil
        //self.transportParams.max_datagram_frame_size = nil
        //self.transportParams.preferredAddress = nil

        // SSL Context
        self.tlsHandler = try! NIOSSLClientHandler(context: tlsContext, serverHostname: nil)
        self.tlsHandler.setQuicDelegate(self)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        logger.trace("handler added")
        self.storedContext = context
        // Install the PacketProtectorHandler in front of us
        do {
            try context.pipeline.syncOperations.addHandler(self.packetProtectorHandler, position: .before(self))
            try context.pipeline.syncOperations.addHandler(self.ackHandler, position: .before(self))
            try context.pipeline.syncOperations.addHandler(self.tlsHandler, position: .after(self))
        } catch {
            logger.error("failed to add handlers", metadata: ["error": .string(String(describing: error))])
            context.fireErrorCaught(error)
        }
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        // We now want to drop the stored context.
        logger.trace("handler removed")
        self.storedContext = nil
    }

    public func channelActive(context: ChannelHandlerContext) {
        logger.trace("channel active")
        // Store our context
        self.storedContext = context
        // Update our state machine
        guard self.state == .idle else {
            context.fireErrorCaught(Errors.InvalidState)
            return
        }
        self.state = .handshaking(.initial)
        context.fireChannelActive()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        logger.trace("channel inactive")
        context.fireChannelInactive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let packet = unwrapInboundIn(data)

        logger.trace("inbound packet", metadata: ["type": .string(String(describing: PacketType(packet.header.firstByte)))])
        //packet.header.inspect()

        switch self.state {
            case .idle:
                logger.warning("read in idle state", metadata: ["packet": .string(String(describing: packet))])
                return

            case .handshaking(let handshakeState):
                switch handshakeState {
                    case .initial:
                        // As a Client, we expect the ServersInitial at this point...
                        guard let serverInitial = packet as? InitialPacket else { logger.error("invalid packet for state", metadata: ["state": .string(String(describing: self.state)), "type": .string(String(describing: PacketType(packet.header.firstByte)))]); return }

                        // Update our DCID (we set our DCID to the inbound packets SourceCID)
                        self.dcid = serverInitial.header.sourceID

                        // Break Payload up into frames and process them... (we expect both an ACK and a Crypto frame)
                        guard serverInitial.payload.count >= 2 else { logger.error("expected ack and crypto frames in server initial"); return }

                        // We expect an ACK frame
                        guard let ack = serverInitial.payload[0] as? Frames.ACK else { logger.error("expected ack frame"); return }
                        guard let cryptoFrame = serverInitial.payload[1] as? Frames.Crypto else { logger.error("expected crypto frame"); return }

                        // ServerHello
                        guard var serverHello = ByteBuffer(bytes: cryptoFrame.data).getTLSServerHello() else { logger.error("expected tls serverhello"); return }
                        if serverHello.count != cryptoFrame.data.count { logger.debug("serverhello contains extra bytes") }

                        // Get our cipher suite
                        guard let sh = try? ServerHello(header: [], payload: &serverHello) else { logger.error("failed to parse serverhello"); return }
                        guard let cs = try? CipherSuite( sh.cipherSuite ) else { logger.error("unsupported cipher suite", metadata: ["suite": .stringConvertible(sh.cipherSuite)]); return }
                        logger.debug("cipher suite", metadata: ["suite": .string(String(describing: cs))])

                        // If we have extra crypto
                        serverInitial.payload.dropFirst(2).forEach {
                            if let cf = $0 as? Frames.Crypto {
                                cf.encode(into: &partialCryptoBuffer)
                            }
                        }

                        // Pass the Crypto Frame along the pipeline (the NIOSSLHandler will pick it up and consume it)
                        var cryptoBuf = ByteBuffer()
                        cryptoFrame.encode(into: &cryptoBuf)
                        context.fireChannelRead(self.wrapInboundOut(cryptoBuf))

                        // Increment our state
                        self.state = .handshaking(.firstHandshake)

                        defer { packetProtectorHandler.allowHandshakeFlush() }

                        return

                    // As a client we expect 2 Handshake packets within this state
                    // - One containing the encrypted extentions and the certificate
                    case .firstHandshake:
                        guard let serverHandshake = packet as? HandshakePacket else { logger.error("invalid packet for state", metadata: ["state": .string(String(describing: self.state)), "type": .string(String(describing: PacketType(packet.header.firstByte))) ]); return }

                        logger.debug("processing first handshake")

                        // Ensure the handshake packet contains a single crypto frame
                        guard let cryptoFrame = serverHandshake.payload.first as? Frames.Crypto else { logger.error("expected crypto frame"); return }

                        // TODO: Ensure this crypto frame contains the TLS Encrypted Extensions and the Certificate

                        var frameBuf = ByteBuffer(bytes: cryptoFrame.data)
                        guard var encryptedExtensions = frameBuf.readTLSEncryptedExtensions() else { logger.error("expected encrypted extensions"); return }
                        guard let certificate = frameBuf.readTLSCertificate() else { logger.error("expected certificate"); return }

                        let quicParamsOffset = encryptedExtensions.firstRange(of: [0x00, 0x39])!
                        var extBuf = ByteBuffer(bytes: encryptedExtensions.dropFirst(quicParamsOffset.startIndex + 4))
                        logger.trace("encrypted extensions", metadata: ["buf": .string(encryptedExtensions.hexString)])
                        logger.trace("ext buf", metadata: ["buf": .string(extBuf.readableBytesView.hexString)])
                        var ext: TransportParams?
                        do {
                            ext = try TransportParams.decode(&extBuf, perspective: .client)
                        } catch {
                            logger.error("failed to decode encrypted extensions", metadata: ["error": .string(String(describing: error))]); return
                        }
                        guard let ext = ext else { logger.error("failed to decode encrypted extensions"); return }
                        logger.debug("server transport params", metadata: ["params": .string(String(describing: ext))])

                        // TODO: Update all of our Connection / Transport Parameters with the Servers Config

                        // Pass the EncryptedExtensions along to NIOSSL
                        var cryptoBuf = ByteBuffer()
                        Frames.Crypto(offset: VarInt(integerLiteral: 0), data: encryptedExtensions).encode(into: &cryptoBuf)
                        context.fireChannelRead(self.wrapInboundOut(cryptoBuf))

                        // Increment our state
                        self.state = .handshaking(.secondHandshake)

                        var cryptoBuf2 = ByteBuffer()
                        Frames.Crypto(offset: VarInt(integerLiteral: 0), data: certificate).encode(into: &cryptoBuf2)
                        context.fireChannelRead(self.wrapInboundOut(cryptoBuf2))

                        if let certVerify = frameBuf.readTLSCertificateVerify() {
                            var cryptoBuf3 = ByteBuffer()
                            Frames.Crypto(offset: VarInt(integerLiteral: 0), data: certVerify).encode(into: &cryptoBuf3)
                            context.fireChannelRead(self.wrapInboundOut(cryptoBuf3))

                            if let finished = frameBuf.readTLSHandshakeFinished() {
                                var cryptoBuf4 = ByteBuffer()
                                Frames.Crypto(offset: VarInt(integerLiteral: 0), data: finished).encode(into: &cryptoBuf4)
                                context.fireChannelRead(self.wrapInboundOut(cryptoBuf4))

                                self.state = .handshaking(.done)
                            }
                        }

                        // If there's extra data in our frame buf (like a partial cert verify frame) write it to our partialCryptoBuffer
                        self.partialCryptoBuffer.writeBuffer(&frameBuf)
                        serverHandshake.payload.dropFirst().forEach {
                            if $0 as? Frames.Crypto != nil {
                                $0.encode(into: &partialCryptoBuffer)
                            } else {
                                logger.debug("extra frame", metadata: ["frame": .string(String(describing: $0))])
                            }
                        }

                        // At this point we should ACK the Server Initial Packet and the first Server Handshake Packet
                        // We do this by sending an empty packet along to our ACKHandler. If the ACKHandler has a pending ACK for that epoch, it'll inject the ACK into the packet, otherwise the empty packet will be dropped by the packet protector handler.
                        let secondInitialHeader = InitialHeader(
                            version: version,
                            destinationID: dcid,
                            sourceID: scid
                        )
                        let secondInitialPacket = InitialPacket(header: secondInitialHeader, payload: [])

                        let firstHandshakeHeader = HandshakeHeader(
                            version: version,
                            destinationID: dcid,
                            sourceID: scid
                        )
                        let firstHandshakePacket = HandshakePacket(header: firstHandshakeHeader, payload: [])

                        context.write( wrapOutboundOut([secondInitialPacket, firstHandshakePacket]), promise: nil)

                        return

                    // - The other containing the Cert Verify and Handshake Finished message
                    case .secondHandshake:
                        guard let serverHandshake = packet as? HandshakePacket else { logger.error("invalid packet for state", metadata: ["state": .string(String(describing: self.state)), "type": .string(String(describing: PacketType(packet.header.firstByte))) ]); return }

                        logger.debug("processing second handshake")

                        // Ensure the handshake packet contains a single crypto frame
                        guard let cryptoFrame = serverHandshake.payload.first as? Frames.Crypto else { logger.error("expected crypto frame"); return }

                        // TODO: Ensure this crypto frame, contains (maybe the TLS Cert Verify) and the TLS handshake done
                        self.partialCryptoBuffer.writeBytes(cryptoFrame.data)
                        logger.trace("partial crypto buffer", metadata: ["buf": .string(self.partialCryptoBuffer.readableBytesView.hexString)])

                        // We might have already processed the certVerify in the previous datagram...
                        if let certVerify = partialCryptoBuffer.readTLSCertificateVerify() {
                            var cryptoBuf1 = ByteBuffer()
                            Frames.Crypto(offset: VarInt(integerLiteral: 0), data: certVerify).encode(into: &cryptoBuf1)
                            context.fireChannelRead(self.wrapInboundOut(cryptoBuf1))
                        }

                        // But we are expecting at least the handshakeFinished frame
                        guard let handshakeFinished = partialCryptoBuffer.readTLSHandshakeFinished() else { logger.error("expected handshake finished"); return }

                        var cryptoBuf2 = ByteBuffer()
                        Frames.Crypto(offset: VarInt(integerLiteral: 0), data: handshakeFinished).encode(into: &cryptoBuf2)
                        context.fireChannelRead(self.wrapInboundOut(cryptoBuf2))

                        self.state = .handshaking(.done)

                        return

                    case .done:
                        logger.debug("handling last handshake")

                        // We expect one more Handshake Packet ack'ing the ones we sent
                        guard let lastServerHandshake = packet as? HandshakePacket else { logger.error("invalid packet for state", metadata: ["state": .string(String(describing: self.state)), "type": .string(String(describing: PacketType(packet.header.firstByte))) ]); return }

                        // The payload should contain a single ACK Frame
                        guard lastServerHandshake.payload.count == 1, let frame = lastServerHandshake.payload.first else { logger.error("expected single ack frame"); return }

                        if let closeFrame = frame as? Frames.ConnectionClose {
                            logger.info("received connection close frame", metadata: ["frame": .string(String(describing: closeFrame))])
                            self.state = .receivedDisconnect
                            return
                        }

                        // Now we're officially Active!
                        self.state = .active

                        // Install our StreamMultiplexer on our pipeline to handle stream frames
                        do {
                            try context.pipeline.syncOperations.addHandler(
                            QuicStreamMultiplexer(channel: context.channel, inboundStreamInitializer: { streamChannel in
                                streamChannel.pipeline.addHandler(StreamStateHandler())
                            }),
                            position: .after(self)
                            )
                        } catch {
                            logger.error("failed to add stream multiplexer", metadata: ["error": .string(String(describing: error))])
                            context.fireErrorCaught(error)
                        }

                        defer { packetProtectorHandler.allowTrafficFlush() }

                        return
                }
            case .active:
                        logger.debug("handling traffic packets")

                guard let trafficPacket = packet as? ShortPacket else { logger.error("invalid traffic packet for state", metadata: ["state": .string(String(describing: self.state)), "type": .string(String(describing: packet.type)), "packet": .string(String(describing: packet))]); return }

                self.handleShortPacketPayloads(context: context, frames: trafficPacket.payload)

                if self.ackHandler.manager.traffic.needsToSendACK {
                    context.write(
                        self.wrapOutboundOut([
                            ShortPacket(
                                header: GenericShortHeader(firstByte: 0b01000001, id: self.dcid, packetNumber: [0x00]),
                                payload: []
                            )
                        ]),
                        promise: nil
                    )
                }

                return

            case .receivedDisconnect:
                logger.debug("received disconnect", metadata: ["header": .string(String(describing: packet.header)), "payload": .string(packet.serializedPayload.hexString)])
                self.handleShortPacketPayloads(context: context, frames: packet.payload)

            case .sentDisconnect:
                logger.debug("sent disconnect", metadata: ["header": .string(String(describing: packet.header)), "payload": .string(packet.serializedPayload.hexString)])
                self.handleShortPacketPayloads(context: context, frames: packet.payload)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var buffer = unwrapOutboundIn(data)
        logger.trace("outbound buffer", metadata: ["buf": .string(buffer.readableBytesView.hexString)])

        switch self.state {
            case .idle:
                logger.warning("write in idle state")
            case .handshaking(let handshakeState):
                switch handshakeState {
                    case .initial:
                        guard let cryptoFrame = buffer.readCryptoFrame() else { logger.error("expected clienthello crypto frame"); return }

                        // We have an initial client hello crypto frame lets bundle it into an InitialPacket and send it along...
                        let initialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: scid)
                        let packet = InitialPacket(header: initialHeader, payload: [cryptoFrame])

                        context.write(self.wrapOutboundOut([packet]), promise: promise)
                        return

                    case .firstHandshake, .secondHandshake, .done:
                        logger.debug("handle handshake write")

                        guard let cryptoFrame = buffer.readCryptoFrame() else { logger.error("expected client handshake done crypto frame"); return }
                        // Send a handshake packet with the Crypto Frame containing the TLS Client Handshake Done frame and an ACK
                        let handshakeHeader = HandshakeHeader(version: version, destinationID: dcid, sourceID: scid) //, packetNumber: pn.bytes(minBytes: 1, bigEndian: true))

                        let handshakePacket = HandshakePacket(header: handshakeHeader, payload: [cryptoFrame])

                        context.write(self.wrapOutboundOut([handshakePacket]), promise: promise)

                        if cryptoFrame.data.prefix(2) == [0x14, 0x00] {
                            // Writing the Handshake Finished Message
                            self.state = .active
                            self.packetProtectorHandler.allowTrafficFlush()

                            // Install our StreamMultiplexer on our pipeline to handle stream frames
                        do {
                            try context.pipeline.syncOperations.addHandler(
                                QuicStreamMultiplexer(channel: context.channel, inboundStreamInitializer: { streamChannel in
                                    streamChannel.pipeline.addHandler(StreamStateHandler())
                                }),
                                position: .after(self)
                            )
                        } catch {
                            logger.error("failed to add stream multiplexer", metadata: ["error": .string(String(describing: error))])
                            context.fireErrorCaught(error)
                        }
                        }

                        return
                }
            case .active:
                logger.debug("handle traffic write")

                var packets: [any Packet] = []

                if self.ackHandler.manager.handshake.needsToSendACK {
                    packets.append(HandshakePacket(header: HandshakeHeader(version: self.version, destinationID: self.dcid, sourceID: self.scid), payload: []))
                }

                // Construct our first Traffic Packet
                let trafficHeader = GenericShortHeader(firstByte: 0b01000001, id: dcid, packetNumber: [0x00])
                guard let streamFrame = buffer.readStreamFrame() else { logger.error("expected stream frame"); return }

                packets.append(ShortPacket(header: trafficHeader, payload: [streamFrame]))

                context.write( wrapOutboundOut(packets), promise: nil)

                return
            case .receivedDisconnect:
                logger.info("TODO: handle received disconnect")
            case .sentDisconnect:
                logger.info("TODO: handle sent disconnect")
        }
    }

    public func flush(context: ChannelHandlerContext) {
        logger.trace("flush")
        context.flush()
    }

    // Flush it out. This can make use of gathering writes if multiple buffers are pending
    public func channelWriteComplete(context: ChannelHandlerContext) {
        logger.trace("channel write complete")
        context.flush()
    }

    public func errorCaught(ctx: ChannelHandlerContext, error: Error) {
        logger.error("error caught", metadata: ["error": .string(String(describing: error))])
        ctx.close(promise: nil)
    }

    private func handleShortPacketPayloads(context: ChannelHandlerContext, frames: [Frame]) {

        for frame in frames {
            logger.trace("frame", metadata: ["frame": .string(String(describing: frame))])
            if let streamFrame = frame as? Frames.Stream {
                logger.trace("stream frame", metadata: ["frame": .string(String(describing: streamFrame))])
                var buf = ByteBuffer()
                streamFrame.encode(into: &buf)
                context.fireChannelRead(self.wrapInboundOut(buf))

                logger.debug("got stream response; sending close")
                //print("ACKing everything, attempting to close")
                //let acks = ackHandler.manager.getAllACKs()
                //print(acks)

                // Close the connection
                let closeFrame = Frames.ConnectionClose(closeType: .quic, errorCode: VarInt(integerLiteral: 0), frameType: nil, reasonPhrase: "")
                // If we have an outstanding ACK for out traffic epoch, include it...
                //if let tACK = ackManager.getACK(for: .Application) ?? acks.traffic { frames.insert(tACK, at: 0) }
                //let closeStream = Frames.Stream(streamID: StreamID(rawValue: VarInt(integerLiteral: 0)), offset: VarInt(integerLiteral: 4), length: VarInt(integerLiteral: 0), fin: true, data: ByteBuffer())
                //closeStream.encode(into: &closeBuf)
                //connClose.encode(into: &closeBuf)
                let packet = ShortPacket(
                    header: GenericShortHeader(
                        firstByte: 0b01000001,
                        id: dcid,
                        packetNumber: [0x00]
                    ),
                    payload: [] // [closeFrame]
                )
                //print("❌ Sending Connection Close Frame ❌")
                context.write(self.wrapOutboundOut([packet]), promise: nil)

                self.state = .sentDisconnect
            }
        }
    }
}
