## SwiftQuic Roadmap to Full QUIC (and HTTP/3) Implementation

This roadmap outlines the plan to evolve SwiftQuic from a functional crypto/parsing core into a fully interoperable QUIC implementation, with verified interop against both quic-go and Quinn (Rust). Quinn interop is top priority because our production node is Rust-based and uses Quinn.

### Goals and Success Criteria
- **Primary interop targets**: Quinn (Rust), quic-go (Go)
- **Protocol versions**: RFC 9000/9001 (QUIC v1) first; draft-29 kept working as long as feasible
- **TLS**: TLS 1.3 integration via NIO SSL; minimize reliance on a custom fork or clearly isolate if necessary
- **Minimum viable product (MVP)**: Stable handshake and bidirectional stream echo with Quinn and quic-go, with basic ACKs, anti-amplification, and packet coalescing
- **Reliability**: No `fatalError` in production code paths; structured error handling and logging
- **Testing**: CI-backed interop suites run consistently on macOS and Linux

### Interoperability Targets and Versions
- **Quinn**: Track a specific Quinn release (e.g., current stable on Rust stable) for repeatable interop. Pin the Rust toolchain version.
- **quic-go**: Track latest v0.x/v1.x release; pin in CI.
- Maintain a compatibility matrix (cipher suites: AES-GCM, ChaCha20-Poly1305; PN lengths; Initial/Handshake/Application; with/without Retry).

## Phased Milestones

### M0 – Hardening and Repo Hygiene
- Replace `fatalError` and panics with typed errors and `context.fireErrorCaught(...)` where appropriate:
  - `Sources/Quic/NIO/Connection/Handlers/PacketProtectorHandler.swift`
  - `Sources/Quic/NIO/Connection/Handlers/AckHandler.swift`
  - `Sources/Quic/NIO/Stream/StreamMuxer.swift` and channel core helpers
- Add structured logging (SwiftLog) with log levels; remove noisy `print` in hot paths
- Unify small state machines into dedicated connection/handshake/stream state handlers; document allowed transitions
- Improve unit test diagnostics; ensure all tests deterministic
- Outcome: Clean builds, no `fatalError` in normal paths, clearer logs

### M1 – Quinn Interop MVP (Handshake + Echo) 
- Handshake to “active” with Quinn client and server; establish bidirectional stream and echo payload
- Implement essentials:
  - Anti-amplification limit for server before address validation
  - Packet coalescing for handshake flights
  - Send ACK frames for ack-eliciting packets (single-range OK initially)
  - Stream open/write/read path in `QuicStreamMultiplexer` without FIXMEs; ensure child channel write/flush works
  - Fix integration tests to actually run Quinn interop locally and in CI (see Testing section)
- Outcome: `swift test` interop suite green for Quinn echo (client↔server), macOS and Linux runners

### M2 – ACKs, Timers, Loss Recovery, Basic Congestion  
- ACK handling:
  - Implement delayed ACK policy and ACK frequency basics
  - Support ACK ranges (at least contiguous ranges) and ECN counts parsing (optional)
  - Separate packet number spaces (Initial/Handshake/Application) rigorously
- Loss detection (RFC 9002): PTO timer, loss detection on ACK and timer; retransmit lost frames
- Congestion control: Start with NewReno; stub Cubic later
- Stream and connection flow control (connection- and stream-level credit windows)
- Outcome: Stable data transfer under moderate loss; correct recovery, no livelock

### M3 – Transport Features and Robustness  
- Version negotiation (v1 + grease), Retry and token integrity (RFC 9001 retry integrity)
- Stateless reset handling
- Path validation and connection migration (basic: single preferred path, validate DCID changes)
- PMTU / max datagram size compliance; anti-head-of-line measures
- Enhanced error mapping to QUIC transport/app errors; graceful close sequences
- Outcome: More robust networking semantics and production-grade resilience

### M4 – Key Update and 0-RTT 
- Implement key update mechanics (receiving and initiating)
- 0-RTT:
  - Session ticket handling from TLS
  - 0-RTT data sending and server-side acceptance/rejection
  - Anti-replay considerations (basic)
- Outcome: Optional advanced features working with Quinn/quic-go where supported

### M5 – HTTP/3  
- H3 control stream (SETTINGS, GOAWAY)
- Request/response over H3 with QPACK (basic static table, defer dynamic table)
- H3 error handling and graceful shutdown
- Outcome: Minimal HTTP/3 client/server for simple requests via Quinn and quic-go backends

## Technical Work Breakdown

### Architecture & State Machines
- Introduce `ConnectionStateHandler` owning:
  - Per-packet-number-space state (Initial/Handshake/Application)
  - ACK manager per space
  - Loss recovery timers and congestion controller
  - Stream manager (open/close/half-close; buffer reassembly; fin handling)
- Refactor `PacketProtectorHandler` to operate only on `ByteBuffer` and surface typed events; remove hardcoded fatal paths
- Normalize errors: `QuicError` (transport/app), `CryptoError`, `ProtocolViolation` with mapping to CONNECTION_CLOSE

### ACK Handling
- Extend `ACKHandler`:
  - Track largest sent/received per space, ack ranges, timestamps
  - Build `ACK` frames with ranges and (optionally) ECN counts
  - Delayed ACK policy (timer-based with coalescing)

### Loss Recovery (RFC 9002)
- Implement PTO/backoff; detect losses from ACK gaps/time-based; mark frames for retransmission
- Retransmit by regenerating frames (do not resend whole packets); new PN assignment

### Congestion Control
- NewReno implementation with slow start, congestion avoidance, fast recovery
- Congestion window applied to bytes in flight across spaces

### Flow Control
- Connection- and stream-level windows; update on `MAX_DATA`/`MAX_STREAM_DATA`
- Generate `MAX_*` frames when thresholds are reached

### Transport Parameters & Retry/Version Negotiation
- Ensure full encode/decode; ignore unknown params per spec
- Implement Retry integrity tag (v1) and client token echo; anti-amplification gating by validation
- Version negotiation logic and greasing

### Key Update & 0-RTT
- Maintain key phase; roll keys on threshold; handle peer-initiated update
- 0-RTT session resumption, data acceptance policy

### Stream Multiplexing
- Finish `QuicStreamMultiplexer`:
  - Proper child channel lifecycle; remove FIXMEs; implement missing channel core methods safely
  - Backpressure integration with flow control and congestion window

### TLS Integration
- Assess `btoms20/swift-nio-ssl` branch viability; either:
  - (A) Isolate fork-specific code behind a small adapter, or
  - (B) Upstream required QUIC hooks and migrate to official NIOSSL if/when available
- Validate secrets delivery timing across spaces; add tests for reorderings

## Testing & CI Strategy

### Unit and Property Tests
- Extend vector tests for:
  - Header protection across PN lengths (1–4) for long/short headers and both ciphers
  - ACK ranges encode/decode; ACK delay
  - Loss recovery timers; PTO; retransmission logic (deterministic with test clocks)
  - Flow control window updates and frame generation

### Integration: Local Interop
- Add `Tests/Interop/` with harnesses for:
  - Quinn server ↔ SwiftQuic client; SwiftQuic server ↔ Quinn client (echo on bidi stream)
  - quic-go same pairs
- Provide scripts (Makefile or SwiftPM plugins) to:
  - Build and run Quinn example server/client in a Rust toolchain container (or via `cargo` if installed)
  - Build and run quic-go example server/client
  - Exchange payloads, validate echoes, and assert handshake success
- Capture pcaps (tcpdump) optionally and store as CI artifacts for debugging

### CI Matrix (GitHub Actions)
- macOS and Ubuntu runners
- Jobs:
  - Swift unit tests
  - Quinn interop tests (Docker with Rust stable + pinned Quinn)
  - quic-go interop tests (pinned version)
  - Lint: SwiftFormat/SwiftLint if desired; no `print` in shipping code paths

### Fuzzing and Robustness
- Frame parser fuzzing (e.g., Swift fuzzers or property-based tests)
- Malformed packet tests to ensure graceful errors not crashes

## Concrete Tasks (Initial Backlog)

### Code Hygiene and Error Handling
- Replace `fatalError` with error returns/logging in:
  - `PacketProtectorHandler.swift` (read/write paths)
  - `AckHandler.swift` default case
  - `StreamMuxer.swift` child channel writing; channel core unimplemented methods
- Introduce SwiftLog; remove most `print` except in tests

### ACK and Timers
- Add delayed-ACK timer per space; build ACK frames when `needsToSendACK` true or timer fires
- Support ACK ranges encoding/decoding (at least simple contiguous ranges)

### Stream Multiplexer
- Implement `childChannelWrite` fully and channel lifecycle; add unit tests using NIO Embedded

### Interop Harness
- Add `Tests/Interop/Quinn/` with scripts to run Quinn echo server/client
- Add `Tests/Interop/Go/` with quic-go echo harness
- Unskip and/or replace existing Go interop tests to use the new harness

### Anti-Amplification & Coalescing
- Enforce server amplification limit until address validation
- Implement coalescing of Initial+Handshake packets where appropriate

### Transport Params and Retry
- Complete encode/decode; ignore unknown params; add tests
- Implement Retry integrity tag; add client token echo handling

## Risks and Mitigations
- **TLS fork drift**: Abstract behind adapter; periodically rebase; explore upstreaming
- **Timer complexity**: Use a central scheduler and deterministic test clocks to keep behavior testable
- **Interop churn**: Pin versions of Quinn/quic-go in CI; document update cadence
- **Performance**: Start with correctness, then profile hot paths (header protection, AEAD, frame encode/decode)

## Acceptance Criteria per Milestone
- M1: Quinn interop echo (both directions), basic ACKs, no `fatalError` in hot paths
- M2: Loss recovery works under synthetic loss; NewReno enabled; flow control prevents overruns
- M3: Retry/version negotiation/stateless reset; migration basic; robust close
- M4: Key update and 0-RTT validated against Quinn/quic-go (as supported)
- M5: Minimal HTTP/3 request/response with settings exchange

## Operational Notes
- Minimum Swift toolchain: Swift 6.1+
- Platforms: macOS 11+, iOS 13+ (server focus first)
- Security: Keep AEAD choices aligned with interop (AES-GCM by default; ChaCha on platforms where AES is slow)

## Next Steps (Week 1 Checklist)
- Create interop harness scaffolding (Quinn + quic-go) and CI jobs (non-blocking initially)
- Replace top-10 `fatalError` occurrences in handlers with errors and tests
- Wire SwiftLog and convert high-traffic `print` to trace/debug logs
- Add an echo stream test through `QuicStreamMultiplexer` using NIO Embedded



