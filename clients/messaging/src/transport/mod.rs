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

use std::{
    future::Future,
    pin::Pin,
    rc::Rc,
    sync::{Arc, atomic::Ordering},
    time::{Duration, SystemTime},
};
use futures::{
    stream::FuturesUnordered,
    FutureExt,
};
use log::{debug, warn};

use boson_api::{
    Result,
    errors::StateError,
    CryptoIdentity,
    Id,
    Identity,
};

use crate::{
    errors::EncodingError,
    ContactHandler,
    ChannelHandler,
    ConversationHandler,
    FriendRequestHandler,
    channel::Channel,
    contact::{Contact, ContactType}
};
use crate::internal::{
    session_context::SessionContext,
    PhotonChannel,
    PhotonContact,
    PhotonConversation,
    PhotonFriendRequest,
    ContactData,
    ContactMutation,
    PhotonChannelMember,
};
use crate::rpc::{
    request::RPCRequest,
    response::Params as ResponseParams
};

pub(super) const MESSAGE_VERSION: u8 = 2;
pub(super) const HANDSHAKE_MESSAGE: u8 = 0;

pub(super) const RPC_TIMEOUT: Duration = Duration::from_secs(15);

impl RpcServer {
    fn persisted_session_key(&self, contact_id: &Id) -> Result<Vec<u8>> {
        let session = self
            .session_contexts
            .lock()
            .unwrap()
            .get(contact_id)
            .cloned()
            .ok_or_else(|| StateError::new("Contact session key is missing"))?;
        self.user_identity
            .encrypt_into(self.user_id(), session.private_key())
    }

    fn persist_contact(&self, contact: &PhotonContact, session_key: Option<&[u8]>) -> Result<()> {
        let photon = contact.clone();
        self.repository
            .borrow_mut()
            .put_contact(self.contacts_revision.get(), &photon, session_key)
    }

    pub(super) fn to_photon_contact_ops(
        contact: &dyn crate::ContactHandler,
    ) -> Result<PhotonContact> {
        let mut data = ContactData::new(
            *contact.id(),
            contact.contact_type() as u8,
            contact.created_at(),
        );
        data.name = contact.name().map(ToString::to_string);
        data.remark = contact.remark().map(ToString::to_string);
        data.tags = contact.tags().map(ToString::to_string);
        data.muted = contact.is_muted();
        data.blocked = contact.is_blocked();
        data.updated_at = contact.updated_at();
        data.revision = contact.revision();
        Ok(PhotonContact::try_from(data)?)
    }

    fn persist_channel(&self, channel: &dyn crate::ChannelHandler) -> Result<()> {
        let key = self.persisted_session_key(channel.id())?;
        let boxed: Channel = Box::new(Self::to_photon_channel(channel)?);
        self.repository
            .borrow_mut()
            .store_channel(self.contacts_revision.get(), &boxed, &key)
    }

    fn session_context(
        &self,
        contact_id: Id,
        session: CryptoIdentity,
        channel: bool,
    ) -> SessionContext {
        let user_identity = Arc::new(self.user_identity.clone());
        let session_identity = Arc::new(session);
        if channel {
            SessionContext::for_channel(contact_id, user_identity, session_identity)
        } else {
            SessionContext::for_user(contact_id, user_identity, session_identity)
        }
    }

    fn origin_timestamp(&self) -> i64 {
        let now = boson_api::as_ms!(SystemTime::now()) as i64;
        let prev = self.origin_timestamp.load(Ordering::SeqCst);
        let next = prev.checked_add(1).unwrap();
        let timestamp = now.max(next);
        let _ = self.origin_timestamp.compare_exchange(
            prev,
            timestamp,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );

        timestamp
    }

    /// Queues a contact resync if one is due and none is already running.
    pub(crate) fn schedule_contact_sync(
        self: &Rc<Self>,
        pending: &mut FuturesUnordered<Pin<Box<dyn Future<Output = ()>>>>,
    ) {
        if self.is_running()
            && self.is_ready()
            && !self.sync_running.get()
            && self.contact_sync_needed.replace(false)
        {
            self.sync_running.set(true);
            let session = self.clone();
            pending.push(
                async move {
                    if let Err(error) = session.sync_contacts().await {
                        warn!("Contact resynchronization failed: {error}");
                    }
                    session.sync_running.set(false);
                }
                .boxed_local(),
            );
        }
    }

    fn close_transport(&self) {
        self.running.set(false);
        self.pending_calls.clear("TODO");
        self.close();
        self.reconnect_at.set(None);
        self.ready.set(false);
        if self.connected.replace(false) {
            self.notify_connection(|l| l.on_disconnected());
        }
    }

    pub(crate) fn user_id(&self) -> &Id {
        self.user_identity.id()
    }

    pub(crate) fn device_id(&self) -> &Id {
        self.device_identity.id()
    }

    pub(crate) fn peer_id(&self) -> &Id {
        self.options.peer_id()
    }

    pub(crate) fn session_context_for(&self, from: &Id) -> Option<SessionContext> {
        self.session_contexts.lock().unwrap().get(from).cloned()
    }

    pub(crate) async fn contact(&self, id: &Id) -> Option<PhotonContact> {
        self.repository.borrow_mut().contact(id).ok().flatten()
    }

    pub(crate) async fn contacts(&self) -> Vec<PhotonContact> {
        self.repository
            .borrow_mut()
            .contacts()
            .ok()
            .unwrap_or_default()
    }

    pub(crate) async fn put_contact(&self, contact: &PhotonContact) -> Result<()> {
        let session_key = self.persisted_session_key(contact.id()).ok();
        let revision = self.contacts_revision.get();
        self.repository
            .borrow_mut()
            .put_contact(revision, contact, session_key.as_deref())?;
        Ok(())
    }

    pub(crate) async fn put_contacts(&self, contacts: &[PhotonContact]) -> Result<()> {
        for contact in contacts {
            self.put_contact(contact).await?;
        }
        Ok(())
    }

    pub(crate) async fn remove_contact(&self, contact_id: &Id) {
        let revision = self.contacts_revision.get();
        if let Err(error) = self
            .repository
            .borrow_mut()
            .remove_contact(revision, contact_id)
        {
            warn!("Failed to remove contact {contact_id}: {error}");
        }
        self.repository
            .borrow_mut()
            .remove_channel(contact_id)
            .ok();
        self.session_contexts.lock().unwrap().remove(contact_id);
    }

    pub(crate) async fn remove_contacts(&self, ids: &[Id]) -> Result<()> {
        assert!(!ids.is_empty(), "No contact IDs specified");

        let revision = self.contacts_revision.get();
        let mutation = ContactMutation::remove(revision, ids.to_vec());
        let request = RPCRequest::contact_mutate(0, mutation);

        let result = self.send_rpccall(self.peer_id(), request).await?;
        let confirmed = match result {
            ResponseParams::ContactMutate(confirmed) => confirmed,
            _ => return Err(EncodingError::new("RPC result is not a contact revision").into()),
        };
        if confirmed < revision || confirmed < self.contacts_revision.get() {
            return Err(StateError::new("Contact removal revision is outdated").into());
        }
        self.contacts_revision.set(confirmed);

        for id in ids {
            self.remove_contact(id).await;
            self.blocked_contacts.lock().unwrap().remove(id);
        }
        self.repository
            .borrow_mut()
            .remove_contacts(confirmed, ids)?;
        self.contact_listener.on_contacts_removed(ids);
        Ok(())
    }

    pub(super) fn to_photon_channel(channel: &dyn crate::ChannelHandler) -> Result<PhotonChannel> {
        let mut data = ContactData::new(
            *channel.id(),
            ContactType::Channel as u8,
            channel.created_at(),
        );
        data.name = channel.name().map(ToString::to_string);
        data.remark = channel.remark().map(ToString::to_string);
        data.tags = channel.tags().map(ToString::to_string);
        data.muted = channel.is_muted();
        data.blocked = channel.is_blocked();
        data.updated_at = channel.updated_at();
        data.revision = channel.revision();
        let contact = PhotonContact::try_from(data)?;
        let members = channel
            .members()
            .iter()
            .map(|member| {
                PhotonChannelMember::new(
                    *member.id(),
                    member.role(),
                    member.joined().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
                )
            })
            .collect();
        Ok(PhotonChannel::new(
            contact,
            *channel.owner(),
            *channel.session_id(),
            channel.permission(),
            channel.notice().map(ToString::to_string),
            channel.is_announced(),
            members,
        ))
    }

    pub(crate) fn channel(&self, id: &Id) -> Option<PhotonChannel> {
        let mut channel = self.repository.borrow_mut().load_channel(id).ok().flatten()?;
        if let Some(session) = self.session_contexts.lock().unwrap().get(id) {
            channel.set_session_id(*session.session_id());
        }
        Some(channel)
    }

    pub(crate) async fn channels(&self) -> Vec<PhotonChannel> {
        let mut channels = self
            .repository
            .borrow_mut()
            .load_channels()
            .unwrap_or_default();
        let sessions = self.session_contexts.lock().unwrap();
        for channel in &mut channels {
            if let Some(session) = sessions.get(channel.id()) {
                channel.set_session_id(*session.session_id());
            }
        }
        channels
    }

    pub(crate) async fn put_channel(&self, channel: PhotonChannel) -> Result<()> {
        self.repository.borrow_mut().put_channel(channel)
    }

    pub(crate) async fn remove_channel(&self, channel_id: &Id) {
        if let Err(error) = self.repository.borrow_mut().remove_channel(channel_id) {
            warn!("Failed to remove channel {channel_id}: {error}");
        }
        self.session_contexts.lock().unwrap().remove(channel_id);
    }

    pub(crate) async fn remove_channels(&self) {
        if let Err(error) = self.repository.borrow_mut().remove_channels() {
            warn!("Failed to remove channels: {error}");
        }
    }

    pub(crate) async fn conversation(&self, id: &Id) -> Option<PhotonConversation> {
        self.repository
            .borrow_mut()
            .conversation(id)
            .ok()
            .flatten()
    }

    pub(crate) async fn conversations(&self) -> Vec<PhotonConversation> {
        self.repository
            .borrow_mut()
            .load_conversations()
            .unwrap_or_default()
    }

    pub(crate) async fn put_conversation(&self, conversation: PhotonConversation) -> Result<()> {
        self.repository.borrow_mut().put_conversation(conversation)
    }

    pub(crate) async fn remove_conversation(&self, id: &Id) -> Result<()> {
        self.repository
            .borrow_mut()
            .remove_messages_in_conversation(id)
            .map(|_| ())
    }

    pub(crate) async fn remove_conversations(&self, ids: &[Id]) -> Result<()> {
        for id in ids {
            self.remove_conversation(id).await?;
        }
        Ok(())
    }

    pub(crate) async fn clear_conversations(&self, id: &Id) -> Result<()> {
        self.repository
            .borrow_mut()
            .remove_messages_in_conversation(id)
            .map(|_| ())
    }

    pub(crate) fn friend_request(&self, id: &Id) -> Option<PhotonFriendRequest> {
        self.repository
            .borrow_mut()
            .load_friend_request(id)
            .unwrap_or_default()
    }

    pub(crate) fn friend_requests(&self) -> Vec<PhotonFriendRequest> {
        self.repository
            .borrow_mut()
            .load_friend_requests()
            .unwrap_or_default()
    }

    pub(crate) fn put_friend_request(&self, request: &PhotonFriendRequest) -> Result<()> {
        self.repository
            .borrow_mut()
            .put_friend_request(request)
    }

    pub(crate) fn remove_friend_request(&self, user_id: &Id) -> Result<()> {
        self.repository
            .borrow_mut()
            .remove_friend_request(user_id)
            .map(|_| ())
    }

    pub(crate) fn remove_friend_requests(&self, user_ids: &[Id]) -> Result<()> {
        for user_id in user_ids {
            self.remove_friend_request(user_id)?;
        }
        Ok(())
    }

    pub(crate) fn clear_friend_requests(&self) -> Result<()> {
        self.repository
            .borrow_mut()
            .clear_friend_requests()
    }

}

mod prelude;
mod rpc_server;
mod transport;
mod dispatch;
mod inbound;
mod outbound;
mod mqtt;
pub(crate) use rpc_server::RpcServer;

#[cfg(test)]
#[path = "../unitests/test_transport.rs"]
mod test_transport;
