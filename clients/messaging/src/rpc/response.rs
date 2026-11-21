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

use std::result::Result as StdResult;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_cbor::Value as CborValue;

use boson_api::{Id, Result};
use crate::errors::EncodingError;
use crate::internal::{
    ChannelInfo,
    ContactSync,
};
use crate::SessionInfo;
use super::{
    error::RPCError,
    method::Method,
};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum Value {
    SessionList(Vec<SessionInfo>),
    SessionRevoke(()),
    ContactMutate(i32),
    ContactSync(ContactSync),
    ChannelCreate(ChannelInfo),
    ChannelDelete(()),
    ChannelOwnershipTransfer(()),
    ChannelSessionKeyRotate(()),
    ChannelInfoUpdate(()),
    ChannelMembersRoleUpdate(Vec<Id>),
    ChannelMembersBan(Vec<Id>),
    ChannelMembersUnban(Vec<Id>),
    ChannelMembersRemove(Vec<Id>),
    ChannelJoin(ChannelInfo),
    ChannelLeave(()),
    ChannelInfo(ChannelInfo),
}

impl Value {
    fn empty(method: Method) -> Option<Self> {
        match method {
            Method::SessionRevoke => Some(Self::SessionRevoke(())),
            Method::ChannelDelete => Some(Self::ChannelDelete(())),
            Method::ChannelOwnershipTransfer => Some(Self::ChannelOwnershipTransfer(())),
            Method::ChannelSessionKeyRotate => Some(Self::ChannelSessionKeyRotate(())),
            Method::ChannelInfoUpdate => Some(Self::ChannelInfoUpdate(())),
            Method::ChannelLeave => Some(Self::ChannelLeave(())),
            _ => None,
        }
    }

    fn decode<T: DeserializeOwned>(value: CborValue) -> Result<T> {
        serde_cbor::value::from_value(value).map_err(|error|
            EncodingError::new(format!("Malformed response parameters: {error}")).into()
        )
    }

    fn from_result(method: Method, value: CborValue) -> Result<Self> {
        let malformed = || EncodingError::new(format!("Malformed result for {method:?}"));

        match (method, value) {
            (Method::SessionList, value @ CborValue::Array(_)) => {
                Ok(Self::SessionList(Self::decode(value)?))
            }
            (Method::SessionRevoke, CborValue::Null) => Ok(Self::SessionRevoke(())),
            (Method::ContactMutate, CborValue::Integer(revision)) => {
                let revision = i32::try_from(revision)
                    .ok()
                    .filter(|revision| *revision >= 0)
                    .ok_or_else(malformed)?;
                Ok(Self::ContactMutate(revision))
            }
            (Method::ContactSync, value @ CborValue::Map(_)) => {
                Ok(Self::ContactSync(Self::decode(value)?))
            }
            (Method::ChannelCreate, value @ CborValue::Map(_)) => {
                Ok(Self::ChannelCreate(Self::decode(value)?))
            }
            (Method::ChannelDelete, CborValue::Null) => Ok(Self::ChannelDelete(())),
            (Method::ChannelOwnershipTransfer, CborValue::Null) => {
                Ok(Self::ChannelOwnershipTransfer(()))
            }
            (Method::ChannelSessionKeyRotate, CborValue::Null) => {
                Ok(Self::ChannelSessionKeyRotate(()))
            }
            (Method::ChannelInfoUpdate, CborValue::Null) => Ok(Self::ChannelInfoUpdate(())),
            (Method::ChannelMembersRoleUpdate, value) => {
                Ok(Self::ChannelMembersRoleUpdate(Self::decode(value)?))
            }
            (Method::ChannelMembersBan, value) => {
                Ok(Self::ChannelMembersBan(Self::decode(value)?))
            }
            (Method::ChannelMembersUnban, value) => {
                Ok(Self::ChannelMembersUnban(Self::decode(value)?))
            }
            (Method::ChannelMembersRemove, value) => {
                Ok(Self::ChannelMembersRemove(Self::decode(value)?))
            }
            (Method::ChannelJoin, value @ CborValue::Map(_)) => {
                Ok(Self::ChannelJoin(Self::decode(value)?))
            }
            (Method::ChannelLeave, CborValue::Null) => Ok(Self::ChannelLeave(())),
            (Method::ChannelInfo, value @ CborValue::Map(_)) => {
                Ok(Self::ChannelInfo(Self::decode(value)?))
            }
            _ => Err(malformed().into()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "RawResponse")]
pub(crate) struct RpcResponse {
    id: i64,
    method: Method,
    result: Option<Value>,
    error: Option<RPCError>,
}

impl RpcResponse {
    pub(crate) fn id(&self) -> i64 {
        self.id
    }

    pub(crate) fn method(&self) -> Method {
        self.method
    }

    pub(crate) fn result(self) -> Result<Value> {
        if let Some(error) = self.error {
            return Err(error.into());
        }
        match self.result {
            Some(result) => Ok(result),
            None => Value::empty(self.method)
                .ok_or_else(|| EncodingError::new(format!("Missing result for {:?}", self.method)).into()),
        }
    }

    pub(crate) fn deserialize(payload: &[u8]) -> Result<Self> {
        serde_cbor::from_slice(payload).map_err(|e|
            EncodingError::new(&format!(
                "deserializing rpc response error: {e}")
            ).into()
        )
    }
}

#[derive(Deserialize)]
struct RawResponse {
    #[serde(rename = "id")]
    id: i64,
    #[serde(rename = "m")]
    method: Method,
    #[serde(rename = "r", default)]
    result: Option<CborValue>,
    #[serde(rename = "e", default)]
    error: Option<RPCError>,
}

impl TryFrom<RawResponse> for RpcResponse {
    type Error = Box<dyn std::error::Error>;

    fn try_from(raw: RawResponse) -> StdResult<Self, Self::Error> {
        if raw.id < 0 {
            return Err(EncodingError::new("Invalid RPC response id").into());
        }
        let result = match raw.result {
            Some(v) => Some(Value::from_result(raw.method, v)?),
            None => None,
        };
        Ok(Self {
            id: raw.id,
            method: raw.method,
            result,
            error: raw.error,
        })
    }
}
