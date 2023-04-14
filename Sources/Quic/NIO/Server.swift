//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol Server: Endpoint {
  static func bootstrap() async throws -> Self

  func accept() async throws -> Connection
}
