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
import Logging

final class ACKChannelHandler: ChannelDuplexHandler {
    public typealias InboundIn = Packet
    public typealias InboundOut = Packet
    public typealias OutboundOut = [any Packet]
    public typealias OutboundIn = [any Packet] // This is an array, so we can explicitly coalesce packets within a datagram

    let manager: ACKManager
    private let logger = Logger(label: "quic.ack")

    init() {
        self.manager = ACKManager()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard let numberedPacket = self.unwrapInboundIn(data) as? any NumberedPacket else {
            context.fireChannelRead(data)
            return
        }
        // Pass the numbered packet into the ack manager for processing...
        self.manager.process(numberedHeader: numberedPacket.header, isAckEliciting: self.isPacketAckEliciting(numberedPacket))

        // Search the packets payload for Ack Frames and process them...
        for frame in numberedPacket.payload {
            if let ack = frame as? Frames.ACK {
                switch numberedPacket.type {
                    case .Initial:
                        self.manager.process(ack: ack, for: .Initial)
                    case .Handshake:
                        self.manager.process(ack: ack, for: .Handshake)
                    case .Short:
                        self.manager.process(ack: ack, for: .Application)
                    default:
                        logger.warning("Unhandled packet type in ACK channel read", metadata: ["type": .string(String(describing: numberedPacket.type))])
                }
            }
        }

        // Forward the original data along, unaltered
        context.fireChannelRead(data)
    }

    private func isPacketAckEliciting(_ packet: any NumberedPacket) -> Bool {
        if packet.payload.count == 1, let onlyFrame = packet.payload.first {
            if onlyFrame as? Frames.ACK != nil { return false }
        }
        return true
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var packets = self.unwrapOutboundIn(data)

        // Inject ACKs when necessary & Set Packet Number
        for i in 0..<packets.count {
            switch packets[i].type {
                case .Initial:
                    guard var initialPacket = packets[i] as? InitialPacket else { context.fireErrorCaught(Errors.InvalidPacket); return }
                    // Set the packet number
                    let pn = self.manager.nextPacketNumber(for: .Initial)
                    logger.trace("Setting PN for Initial", metadata: ["pn": .stringConvertible(pn)])
                    if pn == 0 {
                        initialPacket.header.setPacketNumber(pn.bytes(minBytes: 4, bigEndian: true))
                    } else {
                        initialPacket.header.setPacketNumber(pn.bytes(minBytes: 1, bigEndian: true))
                    }
                    // Inject ACK if necessary
                    if let ack = self.manager.getACK(for: .Initial) {
                        logger.trace("Injecting ACK into Initial packet")
                        initialPacket.payload.insert(ack, at: 0)
                    }
                    // Update the packet
                    packets[i] = initialPacket

                case .Handshake:
                    guard var handshakePacket = packets[i] as? HandshakePacket else { context.fireErrorCaught(Errors.InvalidPacket); return }
                    let pn = self.manager.nextPacketNumber(for: .Handshake)
                    logger.trace("Setting PN for Handshake", metadata: ["pn": .stringConvertible(pn)])
                    // Set the packet number
                    handshakePacket.header.setPacketNumber(pn.bytes(minBytes: 1, bigEndian: true))
                    // Inject ACK if necessary
                    if let ack = self.manager.getACK(for: .Handshake) {
                        logger.trace("Injecting ACK into Handshake packet")
                        handshakePacket.payload.insert(ack, at: 0)
                    }
                    // Update the packet
                    packets[i] = handshakePacket
                case .Short:
                    guard var trafficPacket = packets[i] as? ShortPacket else { context.fireErrorCaught(Errors.InvalidPacket); return }
                    let pn = self.manager.nextPacketNumber(for: .Application)
                    logger.trace("Setting PN for Application", metadata: ["pn": .stringConvertible(pn)])
                    // Set the packet number
                    trafficPacket.header.setPacketNumber(pn.bytes(minBytes: 2, bigEndian: true))
                    // Inject ACK if necessary
                    if let ack = self.manager.getACK(for: .Application) {
                        logger.trace("Injecting ACK into Application packet")
                        trafficPacket.payload.insert(ack, at: 0)
                    }
                    // Update the packet
                    packets[i] = trafficPacket
                default:
                    logger.warning("Unhandled packet type on write", metadata: ["header": .string(String(describing: packets[i].header))])
            }
        }

        // Pass the packets along to the PacketProtectorHandler
        context.write(self.wrapOutboundOut(packets), promise: promise)
    }

    public func flushPendingACKs(context: ChannelHandlerContext, promise: EventLoopPromise<Void>?) {
    }
}

final class ACKHandler {
    let epoch: Epoch
    // The largest packet number acked by our peer
    var largestSentAcked: UInt64?

    // The largest packet number we've sent
    var largestSent: UInt64!

    // The largest packet number we've acked
    var largestReceivedAcked: UInt64?

    // The largeset packet number we've received
    var largestReceived: UInt64! {
        didSet { self.receivedTimestamp = DispatchTime.now().uptimeNanoseconds }
    }

    var receivedTimestamp: UInt64?

    var needsToSendACK: Bool {
        guard self.largestReceived != nil else { return false }
        if let largestReceivedAcked {
            if self.largestReceived > largestReceivedAcked {
                return true
            } else {
                return false
            }
        } else {
            return true
        }
    }

    init(epoch: Epoch) {
        self.epoch = epoch
    }

    func nextPacketNumber() -> UInt64 {
        if self.largestSent == nil { self.largestSent = 0; return 0 }
        let pn = self.largestSent + 1
        self.largestSent += 1
        return pn
    }

    // Processes an inbound ACK and updates our largestSentAcked value
    func processACK(_ ack: Frames.ACK) {
        if let existingAck = self.largestSentAcked {
            guard existingAck < ack.largestAcknowledged.rawValue else { return }
            self.largestSentAcked = ack.largestAcknowledged.rawValue
        } else {
            self.largestSentAcked = ack.largestAcknowledged.rawValue
        }
    }

    func processReceivedPacketNumber(_ pn: [UInt8], isAckEliciting: Bool) {
        var packetNumber = pn.drop(while: { $0 == 0 })
        if packetNumber.isEmpty { packetNumber = [0x00] }
        guard let num = packetNumber.readQuicVarInt()?.value else {
            // Treat as invalid packet number; mark error and return gracefully
            return
        }
        if self.largestReceived == nil { self.largestReceived = num }
        else if self.largestReceived < num {
            self.largestReceived = num
        }
        if isAckEliciting == false {
            if let recAck = self.largestReceivedAcked, recAck < num {
                self.largestReceivedAcked = num
            } else {
                self.largestReceivedAcked = num
            }
        }
    }

    func writeACKIfNecessary(into buffer: inout ByteBuffer) {
        if let ack = self.getACKIfNecessary() {
            ack.encode(into: &buffer)
        }
    }

    func getACKIfNecessary() -> Frames.ACK? {
        guard self.largestReceived != nil else { return nil }
        if let largestReceivedAcked {
            if self.largestReceived > largestReceivedAcked {
                // Write an ack for the largestReceived packet number...
                let delay: UInt64
                if let received = self.receivedTimestamp {
                    delay = (DispatchTime.now().uptimeNanoseconds - received) / 1000
                } else { delay = 0 }
                let ack = Frames.ACK(largestAcknowledged: VarInt(integerLiteral: self.largestReceived), delay: VarInt(integerLiteral: delay), firstAckRange: VarInt(integerLiteral: 0), ranges: [], ecnCounts: nil)
                self.largestReceivedAcked = self.largestReceived
                return ack
            } else {
                return nil
            }
        } else { // we havent sent an ACK yet... send our first one
            let delay: UInt64
            if let received = self.receivedTimestamp {
                delay = (DispatchTime.now().uptimeNanoseconds - received) / 1000
            } else { delay = 0 }
            let ack = Frames.ACK(largestAcknowledged: VarInt(integerLiteral: self.largestReceived), delay: VarInt(integerLiteral: delay), firstAckRange: VarInt(integerLiteral: 0), ranges: [], ecnCounts: nil)
            self.largestReceivedAcked = self.largestReceived
            return ack
        }
    }
}

struct ACKManager {
    let initial: ACKHandler = ACKHandler(epoch: .Initial)
    let handshake: ACKHandler = ACKHandler(epoch: .Handshake)
    let traffic: ACKHandler = ACKHandler(epoch: .Application)

    /// This method lets us know if there are outstanding ACKs that need to be sent to the remote peer
    var needsToSendACK: Bool {
        self.initial.needsToSendACK || self.handshake.needsToSendACK || self.traffic.needsToSendACK
    }

    /// This method should be called for every inbound ACK Frame we receive
    func process(ack: Frames.ACK, for epoch: Epoch) {
        switch epoch {
            case .Initial: self.initial.processACK(ack)
            case .Handshake: self.handshake.processACK(ack)
            case .Application: self.traffic.processACK(ack)
        }
    }

    /// This method should be called for every inbound packet we receive
    func process(numberedHeader: NumberedHeader, isAckEliciting: Bool = true) {
        switch PacketType(numberedHeader.firstByte) {
            case .Initial:
                self.initial.processReceivedPacketNumber(numberedHeader.packetNumber, isAckEliciting: true)
            case .Handshake:
                self.handshake.processReceivedPacketNumber(numberedHeader.packetNumber, isAckEliciting: true)
            case .Short:
                self.traffic.processReceivedPacketNumber(numberedHeader.packetNumber, isAckEliciting: isAckEliciting)
            default:
                return
        }
    }

    /// This method will return the next PacketNumber to use for a given a Epoch
    func nextPacketNumber(for epoch: Epoch) -> UInt64 {
        switch epoch {
            case .Initial: return self.initial.nextPacketNumber()
            case .Handshake: return self.handshake.nextPacketNumber()
            case .Application: return self.traffic.nextPacketNumber()
        }
    }

    func getAllACKs() -> (initial: Frames.ACK?, handshake: Frames.ACK?, traffic: Frames.ACK?) {
        return (
            initial: self.initial.getACKIfNecessary(),
            handshake: self.handshake.getACKIfNecessary(),
            traffic: self.traffic.getACKIfNecessary()
        )
    }

    func getACK(for epoch: Epoch) -> Frames.ACK? {
        switch epoch {
            case .Initial: return self.initial.getACKIfNecessary()
            case .Handshake: return self.handshake.getACKIfNecessary()
            case .Application: return self.traffic.getACKIfNecessary()
        }
    }
}
