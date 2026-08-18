//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A ``NIOSSHClientUserAuthenticationDelegate`` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentictation methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>)

    /// Called when the server sends an SSH_MSG_USERAUTH_BANNER during
    /// authentication (RFC 4252 §5.4). Upstream NIOSSH parses this message
    /// off the wire, validates it belongs in the current state, and then
    /// discards its content — there was previously no way for a client to
    /// ever see it. codeine-go patch: forward it instead.
    ///
    /// This exists because Tailscale SSH sends its periodic re-approval
    /// check ("visit https://login.tailscale.com/a/... to authenticate")
    /// exactly this way, in-band, mid-handshake — not as a keyboard-
    /// interactive prompt, not as a distinct auth method.
    ///
    /// Default implementation is a no-op, so every existing conformer of
    /// this protocol keeps compiling unchanged.
    ///
    /// - parameter message: The banner text, exactly as sent by the server.
    func receivedUserAuthBanner(_ message: String)
}

public extension NIOSSHClientUserAuthenticationDelegate {
    func receivedUserAuthBanner(_ message: String) {}
}
