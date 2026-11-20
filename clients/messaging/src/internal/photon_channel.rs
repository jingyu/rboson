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
use serde::{Serialize, Deserialize};

use boson_api::{
    utils,
    Id,
    Result,
    Error,
};
use crate::{
    channel::{Permission, Role},
    contact::{ContactType},
};
use crate::{
    ContactHandler,
    ContactEditorHandler,
    ChannelMemberHandler,
    ChannelHandler,
    ChannelEditorHandler
};

use super::{
    PhotonContact,
    PhotonChannelMember,
    ChannelInfo,
};

/// Channel implementation backed by a local contact and its membership list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhotonChannel {
    #[serde(rename = "s", with = "utils::id")]
    owner: Id,

    #[serde(rename = "sid", with = "utils::id")]
    session_id: Id,

    #[serde(rename = "p")]
    permission: i32,

    #[serde(
        rename = "nt",
        default,
        skip_serializing_if = "utils::is_default"
    )]
    notice: Option<String>,

    #[serde(
        rename = "a",
        default,
        skip_serializing_if = "utils::is_default"
    )]
    announced: bool,


    #[serde(flatten)]
    contact: PhotonContact,

    #[serde(skip)]
    members: Vec<PhotonChannelMember>,
}

impl PhotonChannel {
    pub(crate) fn photon_contact(&self) -> PhotonContact {
        self.contact.clone()
    }

    pub(crate) fn new(
        contact: PhotonContact,
        owner: Id,
        session_id: Id,
        permission: Permission,
        notice: Option<String>,
        announced: bool,
        members: Vec<PhotonChannelMember>,
    ) -> Self {
        Self {
            owner,
            session_id,
            permission: permission as i32,
            notice,
            announced,
            contact,
            members,
        }
    }
}

impl TryFrom<&ChannelInfo> for PhotonChannel {
    type Error = Error;

    fn try_from(info: &ChannelInfo) -> Result<Self> {
        Ok(Self {
            owner: *info.owner_id(),
            session_id: *info.session_id(),
            permission: info.permission() as i32,
            notice: info.notice().map(ToString::to_string),
            announced: info.announce(),
            contact: TryFrom::try_from(info)?,
            members: info.members().to_vec(),
        })
    }
}

impl From<Box<PhotonChannel>> for Box<dyn ChannelHandler> {
    fn from(channel: Box<PhotonChannel>) -> Self {
        channel
    }
}

impl AsRef<dyn ChannelHandler> for PhotonChannel {
    fn as_ref(&self) -> &(dyn ChannelHandler + 'static) {
        self
    }
}

impl ContactHandler for PhotonChannel {
    fn id(&self) -> &Id {
        self.contact.id()
    }

    fn contact_type(&self) -> ContactType {
        self.contact.contact_type()
    }

    fn name(&self) -> Option<&str> {
        self.contact.name()
    }

    fn remark(&self) -> Option<&str> {
        self.contact.remark()
    }

    fn tags(&self) -> Option<&str> {
        self.contact.tags()
    }

    fn is_muted(&self) -> bool {
        self.contact.is_muted()
    }

    fn is_blocked(&self) -> bool {
        self.contact.is_blocked()
    }

    fn created_at(&self) -> i64 {
        self.contact.created_at()
    }

    fn updated_at(&self) -> i64 {
        self.contact.updated_at()
    }

    fn revision(&self) -> i32 {
        self.contact.revision()
    }

    fn edit(&self) -> Box<dyn ContactEditorHandler> {
        self.contact.edit()
    }

    fn clone_box(&self) -> Box<dyn ContactHandler> {
        Box::new(self.clone())
    }

    fn set_revision(&mut self, revision: i32) {
        self.contact.set_revision(revision);
    }
}

impl ChannelHandler for PhotonChannel {
    fn permission(&self) -> Permission {
        Permission::from_i32(self.permission)
    }

    fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    fn is_announced(&self) -> bool {
        self.announced
    }

    fn size(&self) -> usize {
        self.members.len()
    }

    fn banned(&self) -> usize {
        self.members.iter().filter(|member| member.role() == crate::channel::Role::Banned).count()
    }

    fn members(&self) -> Vec<Box<dyn ChannelMemberHandler>> {
        self.members.iter().cloned().map(|m| Box::new(m) as Box<dyn ChannelMemberHandler>).collect()
    }

    fn member(&self, member_id: &Id) -> Option<Box<dyn ChannelMemberHandler>> {
        self.members
            .iter()
            .find(|member| member.id() == member_id)
            .cloned()
            .map(|m| Box::new(m) as Box<dyn ChannelMemberHandler>)
    }

    fn edit_channel(&self) -> Box<dyn ChannelEditorHandler> {
        Box::new(PhotonChannelEditor(self.clone())) as Box<dyn ChannelEditorHandler>
    }

    fn clone_box(&self) -> Box<dyn ChannelHandler> {
        Box::new(self.clone())
    }

    fn owner(&self) -> &Id {
        &self.owner
    }

    fn session_id(&self) -> &Id {
        &self.session_id
    }

    fn contact_box(&self) -> Box<dyn ContactHandler> {
        Box::new(self.contact.clone())
    }

    fn set_contact_revision(&mut self, revision: i32) {
        self.contact.set_revision(revision);
    }

    fn set_owner(&mut self, owner: Id) {
        self.owner = owner;
    }

    fn set_session_id(&mut self, session_id: Id) {
        self.session_id = session_id;
    }

    fn set_permission(&mut self, permission: Permission) {
        self.permission = permission as i32;
    }

    fn set_notice(&mut self, notice: Option<String>) {
        self.notice = notice;
    }

    fn set_announced(&mut self, announced: bool) {
        self.announced = announced;
    }

    fn set_name(&mut self, name: Option<String>) {
        self.contact.set_name(name);
    }

    fn set_updated_at(&mut self, updated_at: i64) {
        self.contact.set_updated_at(updated_at);
    }

    fn upsert_member(&mut self, id: Id, role: Role, joined: SystemTime) {
        let joined = joined
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        self.members.retain(|member| member.id() != &id);
        self.members.push(PhotonChannelMember::new(id, role, joined));
    }

    fn update_member_roles(&mut self, ids: &[Id], role: Role) -> Vec<Box<dyn ChannelMemberHandler>> {
        let mut changed = Vec::new();
        for member in &mut self.members {
            if ids.contains(member.id()) {
                let joined = member
                    .joined()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_millis() as u64)
                    .unwrap_or(0);
                *member = PhotonChannelMember::new(*member.id(), role, joined);
                changed.push(Box::new(member.clone()) as Box<dyn ChannelMemberHandler>);
            }
        }
        changed
    }

    fn remove_members(&mut self, ids: &[Id]) -> Vec<Box<dyn ChannelMemberHandler>> {
        let mut removed = Vec::new();
        self.members.retain(|member| {
            if ids.contains(member.id()) {
                removed.push(Box::new(member.clone()) as Box<dyn ChannelMemberHandler>);
                false
            } else {
                true
            }
        });
        removed
    }
}

pub struct PhotonChannelEditor(PhotonChannel);

impl ChannelEditorHandler for PhotonChannelEditor {
    fn permission(mut self: Box<Self>, permission: Permission) -> Box<dyn ChannelEditorHandler> {
        self.0.permission = permission as i32;
        self
    }

    fn name(mut self: Box<Self>, name: String) -> Box<dyn ChannelEditorHandler> {
        self.0.contact.set_name(Some(name));
        self
    }

    fn notice(mut self: Box<Self>, notice: Option<String>) -> Box<dyn ChannelEditorHandler> {
        self.0.notice = notice;
        self
    }

    fn announced(mut self: Box<Self>, announced: bool) -> Box<dyn ChannelEditorHandler> {
        self.0.announced = announced;
        self
    }

    fn build(self: Box<Self>) -> Box<dyn ChannelHandler> {
        Box::new(self.0) as Box<dyn ChannelHandler>
    }
}
