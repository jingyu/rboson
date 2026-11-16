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

use std::time::{Duration, SystemTime};

use boson_api::Id;
use crate::{
    FriendRequest,
    BoxedFriendRequest
};

#[derive(Debug, Clone)]
pub struct PhotonFriendRequest {
    user_id: Id,
    initiator_id: Id,
    hello: Option<String>,
    accepted: bool,

    created_at: u64,
    accepted_at: Option<u64>,
    updated_at: u64,
}

impl PhotonFriendRequest {
    const EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24 * 7); // 1 week

    pub(crate) fn restore(
        user_id: Id,
        initiator_id: Id,
        hello: Option<String>,
        accepted: bool,
        created_at: u64,
        accepted_at: Option<u64>,
        updated_at: u64,
    ) -> Self {
        Self {
            user_id,
            initiator_id,
            hello,
            accepted,
            created_at,
            accepted_at,
            updated_at: if updated_at != 0 { updated_at } else { created_at },
        }
    }

    /// Creates a new outgoing request using the current time.
    pub(crate) fn new(
        user_id: Id,
        initiator_id: Id,
        hello: Option<String>,
        created_at: u64,
    ) -> Self {
        Self {
            user_id,
            initiator_id,
            hello,
            accepted: false,
            created_at,
            accepted_at: None,
            updated_at: created_at,
        }
    }

    /// Creates a record for a request received in a handshake.
    pub(crate) fn received(
        user_id: Id,
        initiator_id: Id,
        hello: Option<String>,
        sent_at: u64,
        now: u64,
    ) -> Self {
        Self {
            user_id,
            initiator_id,
            hello,
            accepted: false,
            created_at: Self::not_in_the_future(sent_at, now),
            accepted_at: None,
            updated_at: now,
        }
    }

    pub(crate) fn not_in_the_future(time: u64, now: u64) -> u64 {
        time.min(now)
    }

    pub(crate) fn accept_now(&mut self) {
        self.accept(boson_api::as_ms!(SystemTime::now()) as u64);
    }

    pub(crate) fn accept(&mut self, timestamp: u64) {
        self.accepted = true;
        self.accepted_at = Some(timestamp);
        self.updated_at = timestamp;
    }

    pub(crate) fn is_expired_at(&self, time: SystemTime) -> bool {
        if self.accepted {
            return false;
        }
        let now = boson_api::as_ms!(time) as u64;
        now.saturating_sub(self.created_at) >= Self::EXPIRATION.as_millis() as u64
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(SystemTime::now())
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn accepted_at(&self) -> Option<u64> {
        self.accepted_at.map(|v| v)
    }

    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }
}

impl FriendRequest for PhotonFriendRequest {
    fn user_id(&self) -> &Id {
        &self.user_id
    }

    fn initiator_id(&self) -> &Id {
        &self.initiator_id
    }

    fn hello(&self) -> Option<&str> {
        self.hello.as_deref()
    }

    fn is_outgoing(&self) -> bool {
        self.initiator_id() != self.user_id()
    }

    fn is_accepted(&self) -> bool {
        self.accepted
    }

    fn is_expired(&self) -> bool {
        self.is_expired_at(SystemTime::now())
    }

    fn created(&self) -> SystemTime {
        boson_api::from_ms!(self.created_at)
    }

    fn accepted(&self) -> Option<SystemTime> {
        self.accepted_at.map(|value| boson_api::from_ms!(value))
    }

    fn updated(&self) -> SystemTime {
        boson_api::from_ms!(self.updated_at)
    }
}

impl Into<BoxedFriendRequest> for PhotonFriendRequest {
    fn into(self) -> BoxedFriendRequest {
        Box::new(self)
    }
}

impl Into<BoxedFriendRequest> for Box<PhotonFriendRequest> {
    fn into(self) -> BoxedFriendRequest {
        self
    }
}
