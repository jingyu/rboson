// Copyright (c) 2023 -      bosonnetwork.io
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::time::SystemTime;

use boson_api::Id;

// Represents a friend request in the messaging system.
// A friend request captures the negotiation between two users to establish
// a friendship, including the initiator, any greeting message, and its status.

pub trait FriendRequest {
    /// Returns the identifier of the user involved in the friend request (the other side).
    fn user_id(&self) -> &Id;

    /// Returns the identifier of the user who initiated the friend request.
    fn initiator_id(&self) -> &Id;

    /// Returns the greeting message (hello message) sent with the request.
    fn hello(&self) -> Option<&str>;

    /// Checks whether this is an outgoing request, one the current user sent.
    fn is_outgoing(&self) -> bool {
        self.initiator_id() != self.user_id()
    }

    /// Checks if the friend request has been accepted.
    fn is_accepted(&self) -> bool;

    /// Checks if the friend request has expired.
    fn is_expired(&self) -> bool;

    /// Returns the timestamp when the friend request was sent, the same on both sides.
    fn created(&self) -> SystemTime;

    /// Returns the timestamp when the friend request was accepted.
    fn accepted(&self) -> Option<SystemTime>;

    /// Returns the timestamp when this record last changed on this device: when the request was sent
    /// or received, or when it was accepted.
    fn updated(&self) -> SystemTime;


}

pub type BoxedFriendRequest = Box<dyn FriendRequest>;
