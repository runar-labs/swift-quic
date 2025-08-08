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

import Foundation
import NIOCore
import NIOSSL
import Logging

final class QUICServerHandler: ChannelDuplexHandler, NIOSSLQuicDelegate {
    public typealias InboundIn = Packet
    public typealias InboundOut = ByteBuffer
    public typealias OutboundOut = [any Packet]
    public typealias OutboundIn = ByteBuffer

    private let remoteAddress: SocketAddress
    private let ackHandler: ACKChannelHandler
    private let packetProtectorHandler: PacketProtectorHandler2
    private let tlsHandler: NIOSSLServerHandler

    private(set) var state: QuicStateMachine.State {
        didSet { logger.debug("state transition", metadata: ["from": .string(String(describing: oldValue)), "to": .string(String(describing: self.state))]) }
    }

    let mode: EndpointRole = .server
    let version: Quic.Version

    var retiredDCIDs: [ConnectionID] = []
    var dcid: Quic.ConnectionID {
        didSet {
            logger.debug("dcid updated", metadata: ["old": .string(oldValue.rawValue.hexString), "new": .string(self.dcid.rawValue.hexString)])
            self.retiredDCIDs.append(oldValue)
        }
    }

    var retiredSCIDs: [ConnectionID] = []
    var scid: Quic.ConnectionID {
        didSet {
            logger.debug("scid updated", metadata: ["old": .string(oldValue.rawValue.hexString), "new": .string(self.scid.rawValue.hexString)])
            self.retiredSCIDs.append(oldValue)
        }
    }

    private var storedContext: ChannelHandlerContext!

    var partialCryptoBuffer: ByteBuffer = ByteBuffer()

    // Quic Delegate Protocol Conformance
    private var ourTransportParams: TransportParams
    private var peerTransportParams: TransportParams?

    var ourParams: [UInt8] {
        logger.trace("accessing server transport params")
        return (try? Array(self.ourTransportParams.encode(perspective: .server).readableBytesView)) ?? []
    }

    var useLegacyQuicParams: Bool {
        self.version == .versionDraft29 ? true : false
    }

    private let logger = Logger(label: "quic.server")

    func onReadSecret(epoch: UInt32, cipherSuite: UInt16, secret: [UInt8]) {
        guard let suite = try? CipherSuite(cipherSuite) else { logger.error("unsupported cipher suite", metadata: ["suite": .stringConvertible(cipherSuite)]); return }
        switch epoch {
            case 2:
                self.packetProtectorHandler.installHandshakeKeys(secret: secret, for: .client, cipherSuite: suite)
            case 3:
                self.packetProtectorHandler.installTrafficKeys(secret: secret, for: .client, cipherSuite: suite)
            default:
                logger.error("unsupported epoch in onReadSecret", metadata: ["epoch": .stringConvertible(epoch)])
        }
    }

    func onWriteSecret(epoch: UInt32, cipherSuite: UInt16, secret: [UInt8]) {
        guard let suite = try? CipherSuite(cipherSuite) else { logger.error("unsupported cipher suite", metadata: ["suite": .stringConvertible(cipherSuite)]); return }
        switch epoch {
            case 2:
                self.packetProtectorHandler.installHandshakeKeys(secret: secret, for: .server, cipherSuite: suite)
            case 3:
                self.packetProtectorHandler.installTrafficKeys(secret: secret, for: .server, cipherSuite: suite)
            default:
                logger.error("unsupported epoch in onWriteSecret", metadata: ["epoch": .stringConvertible(epoch)])
        }
    }

    func onPeerParams(params: [UInt8]) {
        logger.trace("peer transport params", metadata: ["params": .string(params.hexString)])
        var buf = ByteBuffer(bytes: params)
        self.peerTransportParams = try? TransportParams.decode(&buf, perspective: .client)
    }

    public init(_ remoteAddress: SocketAddress, version: Version, destinationID: ConnectionID, sourceID: ConnectionID? = nil, tlsContext: NIOSSLContext) {
        self.remoteAddress = remoteAddress
        self.version = version
        self.state = .idle
        self.ourTransportParams = TransportParams.default

        // Initialize our Connection ID's
        self.dcid = destinationID
        self.dcid = sourceID ?? ConnectionID(randomOfLength: 0) //destinationID ?? ConnectionID(randomOfLength: 18)
        self.scid = ConnectionID(randomOfLength: 5) //sourceID ?? ConnectionID(randomOfLength: 8)

        // Initialize our PacketProtectorHandler
        self.packetProtectorHandler = PacketProtectorHandler2(initialDCID: destinationID, scid: self.scid, version: version, perspective: .server, remoteAddress: remoteAddress)
        self.ackHandler = ACKChannelHandler()

        // Update the transport params with the original destination connection id
        self.ourTransportParams.original_destination_connection_id = destinationID
        self.ourTransportParams.initial_source_connection_id = self.scid
        self.ourTransportParams.max_idle_timeout = 30
        self.ourTransportParams.stateless_reset_token = nil
        self.ourTransportParams.max_udp_payload_size = 1_452
        self.ourTransportParams.initial_max_data = 786_432
        self.ourTransportParams.initial_max_stream_data_bidi_local = 524_288
        self.ourTransportParams.initial_max_stream_data_bidi_remote = 524_288
        self.ourTransportParams.initial_max_stream_data_uni = 524_288
        self.ourTransportParams.initial_max_streams_bidi = 100
        self.ourTransportParams.initial_max_streams_uni = 100
        //self.transportParams.ack_delay_exponent = 3
        //self.transportParams.max_ack_delay = 26
        //self.transportParams.disable_active_migration = true
        //self.transportParams.active_conn_id_limit = 4
        //self.transportParams.retry_source_connection_id = nil
        //self.transportParams.max_datagram_frame_size = nil
        //self.transportParams.preferredAddress = nil

        // SSL Context
        self.tlsHandler = NIOSSLServerHandler(context: tlsContext)
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

        if let chan = context.channel as? QuicConnectionChannel {
            chan.activeDCIDs = [self.scid]
        }
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        // We now want to drop the stored context.
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

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        logger.trace("channel read")

        let packet = unwrapInboundIn(data)

        logger.trace("inbound packet", metadata: ["type": .string(String(describing: PacketType(packet.header.firstByte)))])

        // If we're idle and we just received our first message, bump the state and fire a channelActive event...
        if self.state == .idle {
            self.state = .handshaking(.initial)
            context.fireChannelActive()
        }

        switch self.state {
            case .idle:
                logger.warning("read in idle state")
            case .handshaking(let handshakeState):
                switch handshakeState {
                    case .initial:
                        guard let initialPacket = packet as? InitialPacket else { context.fireErrorCaught(Errors.InvalidPacket); return }
                        // Open the InitialPacket
                        // TODO: Operate on the bytebuffer directly
                        guard let cryptoFrame = initialPacket.payload.first as? Frames.Crypto else { context.fireErrorCaught(Errors.InvalidPacket); return }
                        logger.trace("crypto frame", metadata: ["buf": .string(cryptoFrame.data.hexString)])

                        //For the time being, lets strip out the ClientHello crypto frame and only send that down the pipeline...
                        // TODO: Ensure the CryptoFrame contains a ClientHello
                        guard var clientHelloBytes = ByteBuffer(bytes: cryptoFrame.data).getTLSClientHello() else { context.fireErrorCaught(Errors.InvalidPacket); return }
                        guard let clientHello = try? ClientHello(header: [], payload: &clientHelloBytes) else { context.fireErrorCaught(Errors.InvalidPacket); return }
                        logger.trace("clienthello", metadata: ["val": .string(String(describing: clientHello))])
                        logger.trace("quic params from clienthello")
                        guard let extVal = clientHello.extensions.first(where: { $0.type == [0x00, 0x39] })?.value else { context.fireErrorCaught(Errors.InvalidTransportParam); return }
                        var extBuf = ByteBuffer(bytes: extVal)
                        guard let quicParams = try? TransportParams.decode(&extBuf, perspective: .server) else { context.fireErrorCaught(Errors.InvalidTransportParam); return }
                        logger.debug("client transport params", metadata: ["params": .string(String(describing: quicParams))])

                        var cryptoBuffer = ByteBuffer()
                        cryptoFrame.encode(into: &cryptoBuffer)
                        context.fireChannelRead(wrapInboundOut(cryptoBuffer))
                        return

                    case .firstHandshake, .secondHandshake:
                        logger.debug("TODO: handle handshake")
                        // At this point we're expecting a couple ACKs from the client (an Initial ACK and a Handshake ACK)
                        if let initialPacket = packet as? InitialPacket {
                            logger.debug("processing initial packet")
                            // This packet should only contain an ACK...
                            guard let ack = initialPacket.payload.first as? Frames.ACK else { logger.error("expected ack in server initial"); return }
                            self.packetProtectorHandler.dropInitialKeys()
                        }

                        if let handshakePacket = packet as? HandshakePacket {
                            logger.debug("processing handshake packet")
                            // This packet should contain at least an ACK, but also might contain the clients Handshake Finished crypto frame
                            if let cryptoFrame = handshakePacket.payload.first(where: { $0 as? Frames.Crypto != nil }) as? Frames.Crypto {
                                logger.trace("found crypto frame in second handshake")
                                var cryptoBuffer = ByteBuffer()
                                cryptoFrame.encode(into: &cryptoBuffer)
                                context.fireChannelRead(wrapInboundOut(cryptoBuffer))

                                self.state = .handshaking(.done)

                                // Send an empty Handshake for Acking
                                let hsPacket = HandshakePacket(header: HandshakeHeader(version: version, destinationID: dcid, sourceID: scid), payload: [])
                                context.write(self.wrapOutboundOut([hsPacket]), promise: nil)

                                self.state = .active

                                // Install our StreamMultiplexer on our pipeline to handle stream frames
                                try! context.pipeline.syncOperations.addHandler(
                                    QuicStreamMultiplexer(channel: context.channel, inboundStreamInitializer: { streamChannel in
                                        streamChannel.pipeline.addHandler(StreamStateHandler())
                                    }),
                                    position: .after(self)
                                )

                                defer { packetProtectorHandler.allowTrafficFlush() }

                                return
                            }
                        }

                        return

                    case .done:
                        logger.debug("TODO: handle traffic")
                }
            case .active:
                logger.debug("TODO: handle short/traffic")
                // This should be a stream frame
                guard let traffic = packet as? ShortPacket else { logger.error("expected traffic packet"); return }
                if let streamFrame = traffic.payload.first(where: { ($0 as? Frames.Stream) != nil }) as? Frames.Stream {
                    logger.debug("got stream frame")
                    let echoPacket = ShortPacket(
                        header: GenericShortHeader(firstByte: 0b01000001, id: self.dcid, packetNumber: []),
                        payload: [Frames.HandshakeDone(), streamFrame]
                    )
                    // Echo the stream frame
                    context.write(self.wrapOutboundOut([echoPacket]), promise: nil)
                }

            case .receivedDisconnect:
                logger.info("TODO: handle received disconnect")
            case .sentDisconnect:
                logger.info("TODO: handle sent disconnect")
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var buffer = unwrapOutboundIn(data)
        logger.trace("server write", metadata: ["buf": .string(buffer.readableBytesView.hexString)])

        switch self.state {
            case .idle:
                logger.warning("write in idle state")
            case .handshaking(let handshakeState):
                switch handshakeState {
                    case .initial:
                        logger.debug("handling initial write")
                        // We should have 2 Crypto Frames in our buffer (the ServerHello and the first portion of our ServerHandshake (which includes the Cert and Extensions))
                        // Create the Server Initial Packet
                        guard let cryptoFrame = buffer.readCryptoFrame() else { logger.error("failed to read serverhello"); return }

                        guard var serverHello = ByteBuffer(bytes: cryptoFrame.data).getTLSServerHello() else { logger.error("expected tls serverhello"); return }

                        // Get our chosen cipher suite
                        guard let sh = try? ServerHello(header: [], payload: &serverHello) else { logger.error("failed to parse serverhello"); return }
                        guard let cs = try? CipherSuite( sh.cipherSuite ) else { logger.error("unsupported cipher suite", metadata: ["suite": .stringConvertible(sh.cipherSuite)]); return }
                        logger.debug("cipher suite", metadata: ["suite": .string(String(describing: cs))])

                        // TODO: Update our DCID and SCID
                        //self.dcid = ConnectionID(randomOfLength: 4)
                        //self.scid = ConnectionID(randomOfLength: 4)

                        let serverInitialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: scid)
                        let serverInitialPacket = InitialPacket(header: serverInitialHeader, payload: [cryptoFrame])

                        // Increment our state (or should we wait for the clients ACK?)
                        self.state = .handshaking(.firstHandshake)

                        //print("Buffer State after Initial Packet")
                        //print(buffer.readableBytesView.hexString)

                        // Create the first Server Handshake Packet (consists of the TLS Encrypted Extensions, and Certifcate)
                        guard let completeServerHandshake = buffer.readCryptoFrame() else { logger.error("failed to read serverhandshake"); return }
                        // Splice the completeServerHanshake into parts
                        var serverHandshakeBuffer = ByteBuffer(bytes: completeServerHandshake.data)
                        logger.trace("serverhandshake readable bytes", metadata: ["bytes": .stringConvertible(serverHandshakeBuffer.readableBytes)])
                        guard let encryptedExtensions = serverHandshakeBuffer.readTLSEncryptedExtensions() else { logger.error("failed to read encrypted extensions"); return }
                        guard let certificate = serverHandshakeBuffer.readTLSCertificate() else { logger.error("failed to read certificate"); return }
                        guard let certVerify = serverHandshakeBuffer.readTLSCertificateVerify() else { logger.error("failed to read certificate verify"); return }
                        guard let handshakeFinished = serverHandshakeBuffer.readTLSHandshakeFinished() else { logger.error("failed to read handshake finished"); return }
                        logger.trace("readable bytes after parsing", metadata: ["bytes": .stringConvertible(buffer.readableBytes)])
                        logger.trace("cumulative tls parts", metadata: ["bytes": .stringConvertible(encryptedExtensions.count + certificate.count + certVerify.count + handshakeFinished.count)])
                        // TODO: Update our DCID and SCID
                        let serverHandshakeHeader = HandshakeHeader(version: version, destinationID: dcid, sourceID: scid)
                        let serverHandshakePacket = HandshakePacket(
                            header: serverHandshakeHeader,
                            payload: [
                                Frames.Crypto(
                                    offset: VarInt(integerLiteral: 0),
                                    data: encryptedExtensions + certificate + certVerify
                                )
                            ]
                        )

                        // Coalesce these two packets into our first datagram and write it out!
                        logger.trace("writing coalesced datagram")
                        context.write( wrapOutboundOut([serverInitialPacket, serverHandshakePacket]), promise: nil)

                        let serverHandshakeHeader2 = HandshakeHeader(version: version, destinationID: dcid, sourceID: scid)
                        let serverHandshakePacket2 = HandshakePacket(
                            header: serverHandshakeHeader2,
                            payload: [
                                Frames.Crypto(
                                    offset: VarInt(integerLiteral: UInt64(encryptedExtensions.count + certificate.count + certVerify.count)),
                                    data: handshakeFinished
                                )
                            ]
                        )

                        // Send the second datagram containing the Cert Verify and Finished frames..
                        context.write( wrapOutboundOut([serverHandshakePacket2]), promise: nil)

                        self.state = .handshaking(.secondHandshake)

                        self.packetProtectorHandler.allowHandshakeFlush()
                        self.packetProtectorHandler.allowTrafficFlush()

                        return

                    case .firstHandshake, .secondHandshake:
                        logger.debug("TODO: handle handshake write")

                    case .done:
                        logger.debug("TODO: handle traffic write")
                }
            case .active:
                logger.debug("TODO: handle short/traffic write")
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
}
