//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct Version: RawRepresentable {
  typealias RawValue = UInt32

  private let data: RawValue
  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    data = rawValue
  }
}

extension Version {
  static let negotiation: Version = 0
}

extension Version: ExpressibleByIntegerLiteral {
  init(integerLiteral value: RawValue) {
    self.init(rawValue: value)
  }
}

extension Version: QuicType {
  init(with bytes: UnsafeBufferPointer<UInt8>) {
    let rawPointer = UnsafeRawBufferPointer(bytes)
    self.init(rawValue: RawValue(bigEndian: rawPointer.load(as: RawValue.self)))
  }

  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try Swift.withUnsafeBytes(of: rawValue.bigEndian, body)
  }
}

extension Version: Codable {}

fileprivate extension Version {
  func isNegotiation() -> Bool {
    data == 0
  }

  func isReserved() -> Bool {
    data & 0x0f0f0f0f == 0x0a0a0a0a
  }
}

func isNegotiation(version: Version) -> Bool {
  version.isNegotiation()
}

func isReserved(version: Version) -> Bool {
  version.isReserved()
}
