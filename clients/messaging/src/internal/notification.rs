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

use serde::{Serialize, Deserialize};

use boson_api::{
    utils,
    Id,
    Result
};
use crate::{
    errors::EncodingError,
    MessageOriginated,
    SessionInfo
};
use super::{
    ChannelInfo,
    ChannelInfoUpdate,
    ChannelMembersRole,
    ContactSync,
    PhotonChannelMember,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "e", content = "b")]
pub(crate) enum Body {
    #[serde(rename = "sn")]
    SessionNew(SessionInfo),
    #[serde(rename = "cs")]
    ContactSync(ContactSync),
    #[serde(rename = "cc")]
    ChannelCreate(ChannelInfo),
    #[serde(rename = "cd")]
    ChannelDeletion,
    #[serde(rename = "cj")]
    ChannelJoin(ChannelInfo),
    #[serde(rename = "cl")]
    ChannelLeave,
    #[serde(rename = "cot")]
    ChannelOwnershipTransfer(Id),
    #[serde(rename = "csr")]
    ChannelSessionKeyRotate(#[serde(with = "utils::bytes")] Vec<u8>),
    #[serde(rename = "ciu")]
    ChannelInfoUpdate(ChannelInfoUpdate),
    #[serde(rename = "cru")]
    ChannelMembersRoleUpdate(ChannelMembersRole),
    #[serde(rename = "cmb")]
    ChannelMembersBan(Vec<Id>),
    #[serde(rename = "cmu")]
    ChannelMembersUnban(Vec<Id>),
    #[serde(rename = "cmr")]
    ChannelMembersRemove(Vec<Id>),
    #[serde(rename = "cmj")]
    ChannelMemberJoin(PhotonChannelMember),
    #[serde(rename = "cml")]
    ChannelMemberLeave(Id),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Notification {
    #[serde(rename = "id")]
    id: Id,
    #[serde(rename = "s")]
    source: Id,
    #[serde(rename = "t")]
    timestamp: u64,
    #[serde(flatten)]
    body: Body,
}

impl Notification {
    pub(crate) fn id(&self) -> &Id {
        &self.id
    }

    pub(crate) fn source(&self) -> &Id {
        &self.source
    }

    pub(crate) fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub(crate) fn body(&self) -> &Body {
        &self.body
    }

    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        serde_cbor::to_vec(self).map_err(|e|
            EncodingError::new(&format!("serializing notification error: {e}")).into()
        )
    }

    pub(crate) fn deserialize(payload: &[u8]) -> Result<Self> {
        serde_cbor::from_slice(payload).map_err(|e|
            EncodingError::new(&format!("deserializing notification error: {e}")).into()
        )
    }
}

impl MessageOriginated for Notification {
    fn id(&self) -> &Id {
        &self.id
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

#[cfg(test)]
#[path = "../unitests/test_notification.rs"]
mod test_notification;
