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

import NIOCore
import Logging

final class PacketProtectorHandler: ChannelDuplexHandler {
    public typealias InboundIn = AddressedEnvelope<ByteBuffer>
    public typealias InboundOut = Packet
    public typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    public typealias OutboundIn = [any Packet] // This is an array, so we can explicitly coallese packets within a datagram

    private let perspective: EndpointRole
    private let scid: ConnectionID

    internal var initialKeys: PacketProtector
    internal var handshakeKeys: PacketProtector
    internal var trafficKeys: PacketProtector
    private var storedContext: ChannelHandlerContext!

    private let remoteAddress: SocketAddress
    private let log = Logger(label: "quic.packetprotector")

    private var canFlushHandshakeBuffer: Bool = false {
        didSet { if self.canFlushHandshakeBuffer && self.encryptedHandshakeBuffer.readableBytes > 0 && self.handshakeKeys.opener != nil { self.decryptAndFlushHandshakeBuffer() } }
    }

    internal var encryptedHandshakeBuffer: ByteBuffer = ByteBuffer()

    private var canFlushTrafficBuffer: Bool = false {
        didSet { if self.canFlushTrafficBuffer && self.encryptedTrafficBuffer.readableBytes > 0 && self.trafficKeys.opener != nil { self.decryptAndFlushTrafficBuffer() } }
    }

    internal var encryptedTrafficBuffer: ByteBuffer = ByteBuffer()

    init(initialDCID dcid: ConnectionID, scid: ConnectionID, version: Version, perspective: EndpointRole, remoteAddress: SocketAddress) {
        self.perspective = perspective
        self.scid = scid
        self.remoteAddress = remoteAddress
        // Generate Initial Key Sets
        self.initialKeys = try! version.newInitialAEAD(connectionID: dcid, perspective: perspective)
        self.handshakeKeys = PacketProtector(epoch: .Handshake, version: version)
        self.trafficKeys = PacketProtector(epoch: .Handshake, version: version)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        self.storedContext = context
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.storedContext = nil
    }

    deinit {
        self.storedContext = nil
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = self.unwrapInboundIn(data)
        log.trace("inbound datagram", metadata: ["size": .stringConvertible(envelope.data.readableBytes)])
        //print(envelope.data.readableBytesView.hexString)

        // TODO: We should be comparing DCID here, or we just trust the Muxer to do it's job and operate on ByteBuffers instead of AddressedEnvelopes.
        //guard envelope.remoteAddress == context.channel.remoteAddress! else {
        //    print("QUICClientHandler::ChannelRead::Remote Address Mismatch \(envelope.remoteAddress) != \(context.channel.remoteAddress!)")
        //    return
        //}

        var buffer = envelope.data

        // Read the packets
        var packetsToProcess: [any Packet] = []
        packetLoop: while buffer.readableBytes > 0 {
            // Determine the Packet Type
            guard let firstByte = buffer.getBytes(at: buffer.readerIndex, length: 1)?.first else { break }
            // Decrypt the Packet (or buffer it if we don't have the keys yet)
            var packet: (any Packet)?
            switch PacketType(firstByte) {
                case .Initial:
                    guard let p = buffer.readEncryptedQuicInitialPacket(using: initialKeys) else {
                        context.fireErrorCaught(Errors.InvalidPacket)
                        break
                    }
                    packet = p
                case .Handshake:
                    guard self.handshakeKeys.opener != nil else {
                        log.debug("buffering handshake packet: keys not yet available")
                        guard let (_, totalPacketLength) = try? buffer.getLongHeaderPacketNumberOffsetAndTotalLength() else {
                            context.fireErrorCaught(Errors.InvalidPacket)
                            break
                        }
                        guard var encryptedPacket = buffer.readSlice(length: totalPacketLength) else {
                            context.fireErrorCaught(Errors.InvalidPacket)
                            break
                        }
                        self.encryptedHandshakeBuffer.writeBuffer(&encryptedPacket)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicHandshakePacket(using: handshakeKeys) else {
                        context.fireErrorCaught(Errors.InvalidPacket)
                        break
                    }
                    packet = p
                case .Short:
                    guard self.trafficKeys.opener != nil else {
                        log.debug("buffering traffic packet: keys not yet available")
                        self.encryptedTrafficBuffer.writeBuffer(&buffer)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicTrafficPacket(dcid: scid, using: trafficKeys) else {
                        context.fireErrorCaught(Errors.InvalidPacket)
                        break
                    }
                    packet = p

                default:
                    context.fireErrorCaught(Errors.InvalidPacket)
                    break
            }
            if let packet {
                packetsToProcess.append(packet)
            }
        }

        // Send each packet along the pipeline
        log.trace("decoded packets", metadata: ["count": .stringConvertible(packetsToProcess.count)])
        packetsToProcess.forEach { packet in
            context.fireChannelRead(self.wrapInboundOut(packet))
        }

        // Notify that we finished reading
        //context.fireChannelReadComplete()
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var packets = self.unwrapOutboundIn(data)

        // Check for the inclusion of InitialPackets and pad the datagram if so!
        self.padDatagramIfNecessary(packets: &packets)

        var datagramPayload = ByteBuffer()

        packets.forEach { packet in
            // Drop truly empty packets (e.g. timer-triggered when no ACK is pending)
            guard packet.payload.isEmpty == false else { log.debug("dropping empty outbound packet"); return }

            log.trace("encrypting packet", metadata: ["type": .string(String(describing: PacketType(packet.header.firstByte)))])

            do {
                let enc: (protectedHeader: [UInt8], encryptedPayload: [UInt8])
                switch PacketType(packet.header.firstByte) {
                    case .Initial:
                        enc = try (packet as! InitialPacket).seal(using: initialKeys)
                    case .Handshake:
                        enc = try (packet as! HandshakePacket).seal(using: handshakeKeys)
                    case .Short:
                        enc = try (packet as! ShortPacket).seal(using: trafficKeys)
                    default:
                        context.fireErrorCaught(Errors.InvalidPacket)
                        return
                }
                datagramPayload.writeBytes(enc.protectedHeader)
                datagramPayload.writeBytes(enc.encryptedPayload)
            } catch {
                context.fireErrorCaught(error)
                return
            }
        }

        // Avoid writing zero-length datagrams
        guard datagramPayload.readableBytes > 0 else {
            promise?.succeed(())
            return
        }

        let datagram = AddressedEnvelope(remoteAddress: remoteAddress, data: datagramPayload)
        log.trace("sending datagram", metadata: ["size": .stringConvertible(datagramPayload.readableBytes)])
        context.writeAndFlush(self.wrapOutboundOut(datagram), promise: promise)
    }

    // This function should be called by our StateHandler
    public func installHandshakeKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .AESGCM128_SHA256) {
        // Given the handshake secret generate the necessary keys for Handshake Packet Protection
        log.debug("install handshake keys", metadata: ["mode": .string(String(describing: mode))])

        // Install the keys
        do {
            try self.handshakeKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushHandshakeBuffer && mode != self.perspective {
                log.trace("attempting to read buffered handshake packets")
                self.decryptAndFlushHandshakeBuffer()
            }
        } catch {
            self.storedContext.fireErrorCaught(error)
        }
    }

    // This function should be called by our StateHandler
    public func installTrafficKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .ChaChaPoly_SHA256) {
        // Given the traffic secret generate the necessary keys for Traffic Packet Protection
        log.debug("install traffic keys", metadata: ["mode": .string(String(describing: mode))])

        // Install the keys
        do {
            try self.trafficKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushTrafficBuffer && mode != self.perspective {
                log.trace("attempting to read buffered traffic packets")
                self.decryptAndFlushTrafficBuffer()
            }
        } catch {
            self.storedContext.fireErrorCaught(error)
        }
    }

    public func allowHandshakeFlush() {
        guard self.canFlushHandshakeBuffer == false else { return }
        self.canFlushHandshakeBuffer = true
    }

    public func allowTrafficFlush() {
        guard self.canFlushTrafficBuffer == false else { return }
        self.canFlushTrafficBuffer = true
    }

    public func dropInitialKeys() {
        self.initialKeys.dropKeys()
    }

    public func dropHandshakeKeys() {
        self.handshakeKeys.dropKeys()
    }

    private func decryptAndFlushHandshakeBuffer() {
        log.trace("flush buffered handshake packets")
        while self.encryptedHandshakeBuffer.readableBytes > 0 {
            guard let packet = encryptedHandshakeBuffer.readEncryptedQuicHandshakePacket(using: self.handshakeKeys) else {
                log.warning("failed to decrypt buffered handshake packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            log.trace("flushing one buffered handshake packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func decryptAndFlushTrafficBuffer() {
        log.trace("flush buffered traffic packets")
        while self.encryptedTrafficBuffer.readableBytes > 0 {
            guard let packet = encryptedTrafficBuffer.readEncryptedQuicTrafficPacket(dcid: self.scid, using: self.trafficKeys) else {
                log.warning("failed to decrypt buffered traffic packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            log.trace("flushing one buffered traffic packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func padDatagramIfNecessary(packets: inout [any Packet]) {
        // If the outbound datagram includes an InitialPacket, it needs to be padded to at least 1200 bytes
        if let initialPacketIndex = packets.firstIndex(where: { $0 as? InitialPacket != nil }) {
            guard var initialPacket = packets[initialPacketIndex] as? InitialPacket else { self.storedContext.fireErrorCaught(Errors.InvalidPacket); return }
            // Get the total estimated bytes for all the packets
            var estimatedLength = 0
            for packet in packets {
                estimatedLength += packet.headerBytes.count + packet.serializedPayload.count + 16
            }

            // Construct our Padding Frame of appropriate length
            let padding = Frames.Padding(length: 1248 - estimatedLength)

            // Inject the padding into our initial packet so it gets encrypted
            initialPacket.payload.insert(padding, at: 0)
            log.trace("padding initial packet", metadata: ["pad": .stringConvertible(1248 - estimatedLength)])

            // Update the packet in our packet array
            packets[initialPacketIndex] = initialPacket
        }

        // TODO: Check if short packet is long enough...
    }
}

/// The only difference between this Handler and PacketProtectorHandler is that it opperates on ByteBuffers instead of AddressedEnvelopes
final class PacketProtectorHandler2: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = Packet
    public typealias OutboundOut = ByteBuffer
    public typealias OutboundIn = [any Packet] // This is an array, so we can explicitly coallese packets within a datagram

    private let perspective: EndpointRole
    private let scid: ConnectionID

    internal var initialKeys: PacketProtector
    internal var handshakeKeys: PacketProtector
    internal var trafficKeys: PacketProtector
    private var storedContext: ChannelHandlerContext!

    private let remoteAddress: SocketAddress
    private let log = Logger(label: "quic.packetprotector2")

    private var canFlushHandshakeBuffer: Bool = false {
        didSet { if self.canFlushHandshakeBuffer && self.encryptedHandshakeBuffer.readableBytes > 0 && self.handshakeKeys.opener != nil { self.decryptAndFlushHandshakeBuffer() } }
    }

    internal var encryptedHandshakeBuffer: ByteBuffer = ByteBuffer()

    private var canFlushTrafficBuffer: Bool = false {
        didSet { if self.canFlushTrafficBuffer && self.encryptedTrafficBuffer.readableBytes > 0 && self.trafficKeys.opener != nil { self.decryptAndFlushTrafficBuffer() } }
    }

    internal var encryptedTrafficBuffer: ByteBuffer = ByteBuffer()

    // Anti-amplification tracking (server-side)
    private var antiAmplificationValidated: Bool = false
    private var bytesReceivedFromPeer: Int = 0
    private var bytesSentToPeer: Int = 0
    private var amplificationSendQueue: [ByteBuffer] = []

    init(initialDCID dcid: ConnectionID, scid: ConnectionID, version: Version, perspective: EndpointRole, remoteAddress: SocketAddress) {
        self.perspective = perspective
        self.scid = scid
        self.remoteAddress = remoteAddress
        // Generate Initial Key Sets
        self.initialKeys = try! version.newInitialAEAD(connectionID: dcid, perspective: perspective)
        self.handshakeKeys = PacketProtector(epoch: .Handshake, version: version)
        self.trafficKeys = PacketProtector(epoch: .Handshake, version: version)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        self.storedContext = context
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.storedContext = nil
    }

    deinit {
        self.storedContext = nil
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = self.unwrapInboundIn(data)

        // Track received bytes for anti-amplification prior to address validation
        self.bytesReceivedFromPeer &+= buffer.readableBytes

        log.trace("inbound buffer", metadata: ["size": .stringConvertible(buffer.readableBytes)])

        // Read the packets
        var packetsToProcess: [any Packet] = []
        packetLoop: while buffer.readableBytes > 0 {
            // Determine the Packet Type
            guard let firstByte = buffer.getBytes(at: buffer.readerIndex, length: 1)?.first else { break }
            // Decrypt the Packet (or buffer it if we don't have the keys yet)
            var packet: (any Packet)?
            switch PacketType(firstByte) {
                case .Initial:
                    guard let p = buffer.readEncryptedQuicInitialPacket(using: initialKeys) else {
                        context.fireErrorCaught(Errors.InvalidPacket)
                        break
                    }
                    packet = p
                case .Handshake:
                    guard self.handshakeKeys.opener != nil else {
                        log.debug("buffering handshake packet: keys not yet available")
                        guard let (_, totalPacketLength) = try? buffer.getLongHeaderPacketNumberOffsetAndTotalLength() else {
                            context.fireErrorCaught(Errors.InvalidPacket)
                            break
                        }
                        guard var encryptedPacket = buffer.readSlice(length: totalPacketLength) else {
                            context.fireErrorCaught(Errors.InvalidPacket)
                            break
                        }
                        self.encryptedHandshakeBuffer.writeBuffer(&encryptedPacket)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicHandshakePacket(using: handshakeKeys) else {
                        context.fireErrorCaught(Errors.InvalidPacket)
                        break
                    }
                    // Receiving a valid Handshake packet from the peer validates the address
                    if self.antiAmplificationValidated == false {
                        self.antiAmplificationValidated = true
                        self.flushAmplificationQueue(context: context)
                    }
                    packet = p
                case .Short:
                    guard self.trafficKeys.opener != nil else {
                        log.debug("buffering traffic packet: keys not yet available")
                        self.encryptedTrafficBuffer.writeBuffer(&buffer)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicTrafficPacket(dcid: scid, using: trafficKeys) else {
                        context.fireErrorCaught(Errors.InvalidPacket)
                        break
                    }
                    packet = p

                default:
                    context.fireErrorCaught(Errors.InvalidPacket)
                    break
            }
            if let packet {
                packetsToProcess.append(packet)
            }
        }

        // Send each packet along the pipeline
        log.trace("decoded packets", metadata: ["count": .stringConvertible(packetsToProcess.count)])
        packetsToProcess.forEach { packet in
            log.trace("packet", metadata: ["type": .string(String(describing: PacketType(packet.header.firstByte))), "payload": .string(packet.serializedPayload.hexString)])
            context.fireChannelRead(self.wrapInboundOut(packet))
        }

        // Notify that we finished reading
        //context.fireChannelReadComplete()
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var packets = self.unwrapOutboundIn(data)

        // Check for the inclusion of InitialPackets and pad the datagram if so!
        self.padDatagramIfNecessary(packets: &packets)

        var datagramPayload = ByteBuffer()

        for packet in packets {
            guard !packet.payload.isEmpty else { log.debug("dropping empty outbound packet"); continue }

            log.trace("encrypting packet", metadata: ["type": .string(String(describing: PacketType(packet.header.firstByte)))])

            do {
                let enc: (protectedHeader: [UInt8], encryptedPayload: [UInt8])
                switch PacketType(packet.header.firstByte) {
                    case .Initial:
                        enc = try (packet as! InitialPacket).seal(using: self.initialKeys)
                    case .Handshake:
                        enc = try (packet as! HandshakePacket).seal(using: self.handshakeKeys)
                    case .Short:
                        enc = try (packet as! ShortPacket).seal(using: self.trafficKeys)
                    default:
                        context.fireErrorCaught(Errors.InvalidPacket)
                        return
                }
                datagramPayload.writeBytes(enc.protectedHeader)
                datagramPayload.writeBytes(enc.encryptedPayload)
            } catch {
                context.fireErrorCaught(error)
                return
            }
        }

        // Attempt to flush any previously queued datagrams within the current limit
        self.flushAmplificationQueue(context: context)

        // Enforce QUIC anti-amplification prior to address validation (3x bytes received)
        let datagramBytes = datagramPayload.readableBytes
        if self.antiAmplificationValidated == false {
            let allowed = (self.bytesReceivedFromPeer &* 3) &- self.bytesSentToPeer
            if datagramBytes > allowed {
                log.debug("anti-amplification: queueing datagram", metadata: [
                    "bytes": .stringConvertible(datagramBytes),
                    "allowed": .stringConvertible(max(0, allowed)),
                    "rx": .stringConvertible(self.bytesReceivedFromPeer),
                    "tx": .stringConvertible(self.bytesSentToPeer)
                ])
                self.amplificationSendQueue.append(datagramPayload)
                return
            }
        }

        self.bytesSentToPeer &+= datagramBytes
        log.trace("sending datagram", metadata: ["size": .stringConvertible(datagramBytes)])
        context.writeAndFlush(self.wrapOutboundOut(datagramPayload), promise: promise)
    }

    // This function should be called by our StateHandler
    public func installHandshakeKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .AESGCM128_SHA256) {
        // Given the handshake secret generate the necessary keys for Handshake Packet Protection
        log.debug("install handshake keys", metadata: ["mode": .string(String(describing: mode))])

        // Install the keys
        do {
            try self.handshakeKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushHandshakeBuffer && mode != self.perspective {
                log.trace("attempting to read buffered handshake packets")
                self.decryptAndFlushHandshakeBuffer()
            }
        } catch {
            self.storedContext.fireErrorCaught(error)
        }
    }

    // This function should be called by our StateHandler
    public func installTrafficKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .ChaChaPoly_SHA256) {
        // Given the traffic secret generate the necessary keys for Traffic Packet Protection
        log.debug("install traffic keys", metadata: ["mode": .string(String(describing: mode))])

        // Install the keys
        do {
            try self.trafficKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushTrafficBuffer && mode != self.perspective {
                log.trace("attempting to read buffered traffic packets")
                self.decryptAndFlushTrafficBuffer()
            }
        } catch {
            self.storedContext.fireErrorCaught(error)
        }
    }

    public func allowHandshakeFlush() {
        guard self.canFlushHandshakeBuffer == false else { return }
        self.canFlushHandshakeBuffer = true
    }

    public func allowTrafficFlush() {
        guard self.canFlushTrafficBuffer == false else { return }
        self.canFlushTrafficBuffer = true
    }

    public func dropInitialKeys() {
        self.initialKeys.dropKeys()
    }

    public func dropHandshakeKeys() {
        self.handshakeKeys.dropKeys()
    }

    private func decryptAndFlushHandshakeBuffer() {
        log.trace("flush buffered handshake packets")
        while self.encryptedHandshakeBuffer.readableBytes > 0 {
            guard let packet = encryptedHandshakeBuffer.readEncryptedQuicHandshakePacket(using: self.handshakeKeys) else {
                log.warning("failed to decrypt buffered handshake packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            log.trace("flushing one buffered handshake packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func decryptAndFlushTrafficBuffer() {
        log.trace("flush buffered traffic packets")
        while self.encryptedTrafficBuffer.readableBytes > 0 {
            guard let packet = encryptedTrafficBuffer.readEncryptedQuicTrafficPacket(dcid: self.scid, using: self.trafficKeys) else {
                log.warning("failed to decrypt buffered traffic packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            log.trace("flushing one buffered traffic packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func padDatagramIfNecessary(packets: inout [any Packet]) {
        // If the outbound datagram includes an InitialPacket, it needs to be padded to at least 1200 bytes
        if let initialPacketIndex = packets.firstIndex(where: { $0 as? InitialPacket != nil }) {
            guard var initialPacket = packets[initialPacketIndex] as? InitialPacket else { self.storedContext.fireErrorCaught(Errors.InvalidPacket); return }
            // Get the total estimated bytes for all the packets
            var estimatedLength = 0
            for packet in packets {
                estimatedLength += packet.headerBytes.count + packet.serializedPayload.count + 16
            }

            guard estimatedLength < 1248 else { log.warning("packet payload exceeds 1248 bytes; not padding initial packet", metadata: ["bytes": .stringConvertible(estimatedLength)]) ; return }

            // Construct our Padding Frame of appropriate length
            let padding = Frames.Padding(length: 1248 - estimatedLength)

            // Inject the padding into our initial packet so it gets encrypted
            initialPacket.payload.insert(padding, at: 0)
            log.trace("padding initial packet", metadata: ["pad": .stringConvertible(1248 - estimatedLength)])

            // Update the packet in our packet array
            packets[initialPacketIndex] = initialPacket
        }

        // TODO: Check if short packet is long enough...
    }

    private func flushAmplificationQueue(context: ChannelHandlerContext) {
        if self.antiAmplificationValidated {
            // After validation, flush everything
            while self.amplificationSendQueue.isEmpty == false {
                var buf = self.amplificationSendQueue.removeFirst()
                let size = buf.readableBytes
                self.bytesSentToPeer &+= size
                log.trace("flushing queued datagram post-validation", metadata: ["size": .stringConvertible(size)])
                context.write(self.wrapOutboundOut(buf), promise: nil)
            }
            context.flush()
            return
        }

        // Prior to validation, respect 3x limit
        var allowed = (self.bytesReceivedFromPeer &* 3) &- self.bytesSentToPeer
        while self.amplificationSendQueue.isEmpty == false {
            guard let nextSize = self.amplificationSendQueue.first?.readableBytes else { break }
            if nextSize <= allowed {
                var buf = self.amplificationSendQueue.removeFirst()
                self.bytesSentToPeer &+= nextSize
                allowed &-= nextSize
                log.trace("flushing queued datagram within limit", metadata: ["size": .stringConvertible(nextSize), "allowed": .stringConvertible(allowed)])
                context.write(self.wrapOutboundOut(buf), promise: nil)
            } else {
                break
            }
        }
        context.flush()
    }

    // MARK: - Testing Utilities
    /// Marks address validation complete (testing only).
    /// This is intended for unit tests to simulate successful validation without performing a full TLS handshake.
    internal func _testingMarkAddressValidated() {
        self.antiAmplificationValidated = true
    }
}
