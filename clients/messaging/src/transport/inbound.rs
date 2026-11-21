use log::trace;
use serde::Deserialize;

use super::prelude::*;
use crate::internal::notification::{Body, Notification};

use crate::{
    FriendRequest,
    MessageOps,
    MessageOriginated,
};
use crate::rpc::response;
use crate::MessageType;

use crate::internal::photon_message::{
    PhotonMessage,
};

#[derive(Deserialize)]
pub(super) struct ChannelContactInfo {
    #[serde(rename = "o")]
    pub(super) owner: Id,
    #[serde(rename = "p")]
    pub(super) permission: i32,
    #[serde(rename = "nt", default)]
    pub(super) notice: Option<String>,
    #[serde(rename = "a", default)]
    pub(super) announced: bool,
}

pub(super) struct DecodedContact {
    pub(super) contact: PhotonContact,
    pub(super) session: Option<CryptoIdentity>,
    pub(super) channel: Option<PhotonChannel>,
}

pub(super) struct ContactState {
    pub(super) contacts: HashMap<Id, Contact>,
    pub(super) sessions: HashMap<Id, SessionContext>,
    pub(super) channels: HashMap<Id, PhotonChannel>,
    pub(super) revision: i32,
}

impl PhotonMessage {
    fn set_content(&mut self, content: PhotonContent) -> Message {
        self.content = Some(content);
        Box::new(self.clone()) as Message
    }
}

impl RpcServer {
    pub(super) async fn dispatch(
        &self,
        topic: Topic,
        mut message: PhotonMessage
    ) {
        message.set_received();

        let Some(from) = message.from().copied() else {
            warn!("Incoming message has no sender, ignoring it");
            return;
        };
        let recipient = message.recipient();
        let msg_type  = message.message_type();

        match topic {
            Topic::UserInbox => {
                if msg_type == MessageType::Control {
                    warn!("Received {msg_type} message from user inbox, ignoring it");
                    return;
                }
                let conv_id = if recipient == self.user_id() {
                    from
                } else {
                    recipient.clone()
                };
                message.set_converstation_id(conv_id);
            }
            Topic::UserOutbox => {
                if msg_type == MessageType::Control {
                    warn!("Received {msg_type} message from user outbox, ignoring it");
                    return;
                }
                message.set_converstation_id(*recipient);
            }
            Topic::DeviceInbox => {
                if msg_type != MessageType::Control {
                    warn!("Received {msg_type} message from device inbox, ignoring it");
                    return;
                }
                message.set_converstation_id(*recipient);
            }
            _ => {
                warn!("Received {msg_type} message from unsupported topic, ignoring it");
                return;
            }
        }

        if let Err(error) = self.check_and_decrypt_message(&mut message).await {
            warn!("{error}");
            return;
        }

        let _ = match topic {
            Topic::UserInbox => self.process_inbox_message(message, &from).await,
            Topic::DeviceInbox => { self.on_device_inbox_message(message, &from); Ok(()) },
            Topic::UserOutbox => self.process_outbox_message(message, &from).await,
            Topic::DeviceOutbox => {
                warn!("Ignoring message from device outbox");
                return;
            }
        }.map_err(|error| warn!("{error}"));
    }

    async fn check_and_decrypt_message(&self, message: &mut PhotonMessage) -> Result<()> {
        let from = *message.from_or_throw()?;
        let recipient = message.recipient();
        let message_type = message.message_type();
        let payload = match &message.payload {
            Value::Bytes(payload) => payload.clone(),
            _ => return Err(EncodingError::new("Message payload is not binary").into()),
        };

        let decrypted = match message_type {
            MessageType::Content => {
                let Some(conversation_id) = message.conversation_id() else {
                    return Err(StateError::new(
                        "Received a message with no conversation Id")
                    .into());
                };
                let Some(contact) = self.contact(&conversation_id).await else {
                    return Err(StateError::new(format!(
                        "Received a message for unknown contact {conversation_id}"
                    )).into());
                };

                if contact.is_blocked() {
                    return Err(StateError::new(
                        "Received a message from a blocked contact"
                    ).into());
                }
                if contact.contact_type() == ContactType::Channel {
                    // TODO: Channel content uses the channel conversation crypto context.
                } else if contact.contact_type() == ContactType::Auto {
                    return Err(StateError::new(
                        "Received a message from a contact of no friend."
                    ).into());
                }

                // A blocked user's messages in a channel are still delivered: the channel is a shared
				// conversation, and dropping one member's messages would leave holes (replies without
				// what they answer) and a view that differs from the other members'.


                let mut sessions = self.session_contexts.lock().unwrap();
                let session = sessions.get_mut(&conversation_id).ok_or_else(|| {
                    StateError::new(format!("No session context for {conversation_id}"))
                })?;
                if from == *self.user_id() {
                    session.tx_crypto_context()?.decrypt_into(&payload)?
                } else {
                    session.rx_crypto_context_for(&from)?.decrypt_into(&payload)?
                }
            }
            MessageType::Control | MessageType::State => {
                if from == *self.peer_id() {
                    payload
                } else if recipient == self.user_id() {
                    self.user_identity.decrypt_into(&from, &payload).map_err(|error| {
                        AuthenticationError::new(format!("Decrypting {message_type:?} failed: {error}"))
                    })?
                } else {
                    let channel = self.channel(&recipient).ok_or_else(|| {
                        StateError::new(format!("Received a {message_type:?} from unknown channel {recipient}"))
                    })?;
                    if channel.is_blocked() {
                        return Err(StateError::new("Received a message from a blocked channel").into());
                    }
                    let mut sessions = self.session_contexts.lock().unwrap();
                    let session = sessions.get_mut(&recipient).ok_or_else(|| {
                        StateError::new(format!("No channel session context for {recipient}"))
                    })?;
                    session.rx_crypto_context()?.decrypt_into(&payload)?
                }
            }
            MessageType::Handshake => {
                let friend_id = if from == *self.user_id() { recipient } else { &from };
                self.user_identity.decrypt_into(&friend_id, &payload).map_err(|error| {
                    AuthenticationError::new(format!("Decrypting handshake failed: {error}"))
                })?
            }
        };

        message.payload = Value::Bytes(decrypted.clone());
        message.payload_bytes = decrypted;
        Ok(())
    }

    fn on_device_inbox_message(&self, message: PhotonMessage, from: &Id) {
        self.try_on_device_inbox_message(message, from)
            .map_err(|error| warn!("{error}"))
            .ok();
    }

    async fn process_inbox_message(&self, message: PhotonMessage, from: &Id) -> Result<()>{
        match message.message_type() {
            MessageType::Content  => {
                self.process_incoming_content_message(message, from).await
            }
            MessageType::State  => {
                self.process_state_message(message, &from).await
            }
            MessageType::Handshake  => {
                self.process_incoming_handshake(message.clone(), &from)?;
                if let Ok(handshake) = Handshake::deserialize(&message.payload_bytes) {
                    if let HandshakeType::FriendRequestAccept(session_key) = handshake.body {
                        self.accept_friend_handshake(
                            *from,
                            session_key,
                            handshake.timestamp,
                            true,
                        ).await;
                    }
                }
                Ok(())
            }
            MessageType::Control  => {
                warn!("Ignoring control message from user inbox");
                Ok(())
            }
        }
    }

    async fn process_outbox_message(&self, message: PhotonMessage, from: &Id) -> Result<()> {
        match message.message_type() {
            MessageType::Handshake => {
                self.process_outgoing_handshake(message, &from).await?;
                Ok(())
            }
            MessageType::Content => {
                self.on_outbox_content_message(message, from);
                Ok(())
            }
            _ => {
                warn!("Ignoring unsupported message type from user outbox");
                Ok(())
            }
        }
    }

    /*
    async fn on_handshake(&self, topic: Topic, message: PhotonMessage, from: &Id) {
        self.try_on_handshake(topic, message, *from)
            .await
            .map_err(|error| warn!("{error}"))
            .ok();
    }*/

    fn on_outbox_content_message(&self, message: PhotonMessage, from: &Id) {
        if from != self.user_id() {
            warn!("Outbox message has an unexpected sender");
            return;
        }
        self.process_outgoing_content_message(message, *from);
    }

    fn try_on_device_inbox_message(&self, message: PhotonMessage, from: &Id) -> Result<()> {
        if message.message_type() != MessageType::Control {
            return Err(EncodingError::new(
                "Ignoring non-control message from device inbox"
            ));
        }
        if message.recipient() != self.user_id()
            && message.recipient() != self.device_id()
        {
            return Err(EncodingError::new(
                "Ignoring device RPC response for another device"
            ));
        }
        let Value::Bytes(payload) = message.payload else {
            return Err(EncodingError::new(
                "Rpc response payload is not binary, ignoring message"
            ));
        };

        self.process_control_message(&payload, from)
    }

    fn process_control_message(&self, payload: &[u8], from: &Id) -> Result<()> {
        let response = response::RpcResponse::deserialize(payload)?;
        trace!("Received rpc response: {}", response.id());
        self.pending_calls.respond(response, from)
    }

    async fn process_state_message(&self, message: PhotonMessage, from: &Id) -> Result<()> {
        let Value::Bytes(payload) = &message.payload else {
            return Err(EncodingError::new("Notification payload is not binary"));
        };

        let notification = Notification::deserialize(payload)?;
        if notification.source() == self.user_id() &&
            notification.is_originated(self.device_id()) {

            // This notification was triggered by an RPC request from this device.
			// Since the local state was already updated via the RPC response,
			// this redundant notification can be safely ignored.
            trace!("The channel notification originated by this device, ignoring it");
            return Ok(());
        }

        if self.peer_id() == from {
            self.process_peer_notification(notification).await?;
            return Ok(());
        }

        let channel = match self.channel(from) {
            Some(c) => c,
            None => {
                let Body::ChannelJoin(info) = notification.body() else {
                    warn!("Received a notification for unknown channel {from}, ignoring it");
                    return Ok(());
                };

                if info.session_key().is_none() {
                    warn!("Recieved a channel join notification but missing session key from {from}, ignoring it");
                    return Ok(());
                }

                let channel = PhotonChannel::try_from(info)?;
                self.put_channel(channel)?;
                self.channel(from).ok_or_else(|| {
                    StateError::new(&format!("Failed to create channel contact for {from}"))
                })?
            }
        };
        self.process_channel_notification(notification, &channel)
            .await
            .map_err(|e| e.into())
    }

    async fn process_peer_notification(&self, notif: Notification) -> Result<()> {
        match notif.body() {
            Body::SessionNew(v) => {
                self.session_listener.on_new_session(v);
                Ok(())
            },
            Body::ContactSync(v) => {
                self.apply_contact_sync(v).await?;
                if self.connected.get() && !self.stopping.get() && !self.ready.replace(true) {
                    info!("Messaging session is ready");
                    self.notify_connection(|listener| listener.on_ready());
                }
                Ok(())
            },
            Body::ChannelCreate(channel_info) => {
                if channel_info.session_key().is_none() {
                    return Err(StateError::new(
                        &format!("Received a channel create notification but missing session key from {}, ignoring it",
                        self.peer_id()),
                    ));
                }

                trace!("Channel {} created", channel_info.channel_id());
                let new_channel = PhotonChannel::try_from(channel_info)?;

                let channel = match self.channel(channel_info.channel_id()) {
                    Some(v) => {
                        trace!("Channel {} already exists, ignoring duplicate create channel notification",
                            channel_info.channel_id());
                        v
                    }
                    None => {
                        self.put_channel(new_channel.clone())?;
                        new_channel
                    }
                };

                if !channel_info.members().is_empty() {
                    let members = channel_info.members().iter()
                        .map(|member| Box::new(member.clone()) as ChannelMember)
                        .collect::<Vec<_>>();
                    self.repository
                        .borrow_mut()
                        .put_channel_members(channel_info.channel_id(), &members)?;
                }
                self.channel_listener.on_channel_created(&(Box::new(channel.clone()) as Box<dyn ChannelHandler>));
                Ok(())
            },
            _ => {
                Err(StateError::new(
                    &format!("Received an unknown peer notification: ignoring it {notif:?}")
                ))
            }
        }
    }

    async fn process_channel_notification(
        &self,
        notif: Notification,
        channel: &PhotonChannel,
    ) -> Result<()> {
        let channel_id = channel.id();
        match notif.body() {
            Body::ChannelDeletion => {
                trace!("Channel {} deleted", channel_id);
                self.remove_channel(channel.id()).await;
                self.channel_listener.on_channel_deleted(&(Box::new(channel.clone()) as Box<dyn ChannelHandler>));
            }
            Body::ChannelJoin(info) => {
                trace!("Channel {} joined", channel_id);
                if self.channel(channel_id).is_none() {
                    self.put_channel(channel.clone())?;
                }

                if info.members().is_empty() {
                    trace!("Channel {} has no members", channel_id);
                } else {
                    let members = info.members().iter()
                        .map(|member| Box::new(member.clone()) as ChannelMember)
                        .collect::<Vec<_>>();
                    self.repository
                        .borrow_mut()
                        .put_channel_members(channel_id, &members)?;
                }
                self.channel_listener.on_joined_channel(&(Box::new(channel.clone()) as Box<dyn ChannelHandler>));
            }
            Body::ChannelLeave => {
                trace!("Channel {} left", channel_id);
                self.remove_channel(channel.id()).await;
                self.channel_listener.on_left_channel(&(Box::new(channel.clone()) as Box<dyn ChannelHandler>));
            }
            Body::ChannelSessionKeyRotate(encrypted_key) => {
                trace!("Channel {} session key rotation", channel_id);

                let mut channel = match self.channel(&channel_id) {
                    Some(channel) => channel,
                    None => {
                        warn!("Failed to get channel snapshot");
                        return Ok(());
                    }
                };
                if notif.source() != channel.owner() {
                    warn!("Channel session key rotation has an unauthorized source");
                    return Ok(());
                }
                let Some(context) = self.session_context_for(&channel_id) else {
                    warn!("Channel session key is missing");
                    return Ok(());
                };
                let key = match context.decrypt_into(&notif.source(), encrypted_key) {
                    Ok(key) => key,
                    Err(error) => {
                        warn!("Decrypting rotated channel session key failed: {error}");
                        return Ok(());
                    }
                };
                let session = match CryptoIdentity::try_from(key.as_slice()) {
                    Ok(session) => session,
                    Err(error) => {
                        warn!("Invalid rotated channel session key: {error}");
                        return Ok(());
                    }
                };
                channel.set_session_id(*session.id());
                self.session_contexts
                    .lock()
                    .unwrap()
                    .insert(*channel_id, self.session_context(*channel_id, session, true));

                self.put_channel(channel.clone())?;
                self.channel_listener.on_channel_session_key_rotated(&(Box::new(channel.clone()) as Box<dyn ChannelHandler>));
                return Ok(());
            }
            Body::ChannelOwnershipTransfer(_new_owner) => {
                trace!("Channel {} ownership transfer", channel_id);
                /*
                let mut channel = match self.channel_snapshot(&channel_id) {
                    Ok(channel) => channel,
                    Err(error) => {
                        warn!("Failed to get channel snapshot: {error}");
                        return Ok(());
                    }
                };
                let old_owner = *channel.owner();
                channel.set_owner(*new_owner);
                self.channels_cache.borrow_mut().insert(*channel_id, channel.clone());
                self.channel_listener
                    .on_channel_ownership_transferred(&channel, &old_owner, new_owner);
                return Ok(());
                */
            }
            Body::ChannelInfoUpdate(changes) => {
                trace!("Channel {} info updated ", channel_id);

                let mut updated = self.channel(channel_id).ok_or_else(|| {
                    warn!("Failed to get channel snapshot");
                    std::io::Error::new(std::io::ErrorKind::NotFound, "Channel not found")
                })?;
                if let Some(permission) = changes.get_permission() {
                    updated.set_permission(permission);
                }
                if let Some(name) = changes.get_name() {
                    updated.set_name(name.map(ToString::to_string));
                }
                if let Some(notice) = changes.get_notice() {
                    updated.set_notice(notice.map(ToString::to_string));
                }
                if let Some(announced) = changes.get_announced() {
                    updated.set_announced(announced);
                }
                self.put_channel(updated.clone())?;
                self.channel_listener.on_channel_updated(&(Box::new(updated.clone()) as Box<dyn ChannelHandler>));
            }
            Body::ChannelMembersRoleUpdate(update) => {
                trace!("Channel {} members role updated: {} - {:?}",
                    channel_id,
                    update.role(),
                    update.member_ids()
                );

                let mut channel = match self.channel(&channel_id) {
                    Some(channel) => channel,
                    None => {
                        warn!("Failed to get channel snapshot");
                        return Ok(());
                    }
                };
                let changed = channel.update_member_roles(update.member_ids(), update.role());
                self.put_channel(channel.clone())?;
                self.channel_listener
                    .on_channel_members_role_updated(&(Box::new(channel.clone()) as Channel), &changed);
                return Ok(());
            }
            Body::ChannelMembersBan(ids) => {
                let mut channel = match self.channel(&channel_id) {
                    Some(channel) => channel,
                    None => {
                        warn!("Failed to get channel snapshot");
                        return Ok(());
                    }
                };
                let changed = channel.update_member_roles(ids, Role::Banned);
                self.put_channel(channel.clone())?;
                self.channel_listener
                    .on_channel_members_banned(&(Box::new(channel.clone()) as Channel), &changed);
                return Ok(());
            }
            Body::ChannelMembersUnban(ids) => {
                let mut channel = match self.channel(&channel_id) {
                    Some(channel) => channel,
                    None => {
                        warn!("Failed to get channel snapshot");
                        return Ok(());
                    }
                };
                let changed = channel.update_member_roles(ids, Role::Member);
                self.put_channel(channel.clone())?;
                self.channel_listener
                    .on_channel_members_unbanned(&(Box::new(channel.clone()) as Channel), &changed);
                return Ok(());
            }
            Body::ChannelMembersRemove(ids) => {
                let mut channel = match self.channel(&channel_id) {
                    Some(channel) => channel,
                    None => {
                        warn!("Failed to get channel snapshot");
                        return Ok(());
                    }
                };
                let removed = channel.remove_members(ids);
                self.put_channel(channel.clone())?;
                self.channel_listener
                    .on_channel_members_removed(&(Box::new(channel.clone()) as Channel), &removed);
                return Ok(());
            }
            Body::ChannelMemberJoin(member) => {
                if member.joined().duration_since(UNIX_EPOCH).is_err() {
                    warn!("Channel member timestamp is out of range");
                    return Ok(());
                }

                let mut channel = match self.channel(&channel_id) {
                    Some(channel) => channel,
                    None => {
                        warn!("Failed to get channel snapshot");
                        return Ok(());
                    }
                };
                channel.upsert_member(*member.id(), member.role(), member.joined());
                self.put_channel(channel.clone())?;
                self.channel_listener
                    .on_channel_member_joined(&(Box::new(channel.clone()) as Channel), &(Box::new(member.clone()) as ChannelMember));
                return Ok(());
            }
            Body::ChannelMemberLeave(id) => {
                let mut channel = match self.channel(&channel_id) {
                    Some(channel) => channel,
                    None => {
                        warn!("Failed to get channel snapshot");
                        return Ok(());
                    }
                };
                let member = channel.members().into_iter().find(|member| member.id() == id);
                channel.remove_members(&[*id]);
                self.put_channel(channel.clone())?;
                if let Some(member) = member {
                    self.channel_listener
                        .on_channel_member_left(&(Box::new(channel.clone()) as Channel), &member);
                }
                return Ok(());
            }
            body => warn!("Unsupported channel notification: {body:?}"),
        }

        Ok(())
    }

    /// Decodes a contact, keeping the session key and channel metadata that the
    /// opaque document carries for the contact kinds that have them.
    pub(super) fn decode_contact(&self, opaque: &OpaqueContact) -> Result<DecodedContact> {
        let (data, plaintext) = opaque.decode_into(&self.user_identity)?;
        let contact = data.contact(opaque.revision())?;
        let session = data.session(&self.user_identity)?;
        let channel = match contact.contact_type() {
            ContactType::Channel => {
                let info: ChannelContactInfo = serde_cbor::from_slice(&plaintext).map_err(|e| EncodingError::new(format!("Malformed channel contact: {e}")))?;
                let session_id = *session
                    .as_ref()
                    .ok_or_else(|| EncodingError::new("Channel session is missing"))?
                    .id();
                Some(PhotonChannel::new(
                    PhotonContact::try_from(data.clone())?,
                    info.owner,
                    session_id,
                    Permission::try_from(info.permission)?,
                    info.notice,
                    info.announced,
                    Vec::new(),
                ))
            }
            _ => None,
        };
        Ok(DecodedContact {
            contact,
            session,
            channel,
        })
    }

    async fn apply_contact_sync(&self, sync: &ContactSync) -> Result<()> {
        let revision = self.contacts_revision.get();
        if matches!(sync.kind(), SyncType::UpToDate) {
            if sync.revision() == revision {
                return Ok(());
            }
            self.contact_sync_needed.set(sync.revision() > revision);
            return Err(StateError::new(
                "Contact sync revision does not match local state",
            ));
        }

        let previous = self
            .repository
            .borrow_mut()
            .load_contacts()
            .unwrap_or_default()
            .into_iter()
            .map(|contact| (*contact.id(), Box::new(contact) as Contact))
            .collect::<HashMap<_, _>>();
        let sessions = self.session_contexts.lock().unwrap().clone();
        let channels = self
            .repository
            .borrow_mut()
            .load_channels()
            .unwrap_or_default()
            .into_iter()
            .map(|channel| (*channel.id(), channel))
            .collect::<HashMap<_, _>>();
        let mut state = ContactState {
            contacts: previous.clone(),
            sessions,
            channels,
            revision,
        };
        match sync.kind() {
            SyncType::Snapshot => self.apply_snapshot(sync, &mut state)?,
            SyncType::Delta => self.apply_delta(sync, &mut state)?,
            SyncType::UpToDate => unreachable!("handled above"),
        }
        self.commit_contact_state(previous, state)
            .map_err(|e| e.into())
    }

    pub(super) fn apply_snapshot(&self, sync: &ContactSync, state: &mut ContactState) -> Result<()> {
        if sync.revision() < state.revision {
            return Err(StateError::new("Invalid or outdated contact snapshot"));
        }
        state.contacts.clear();
        state.sessions.clear();
        state.channels.clear();
        for opaque in sync.contacts() {
            if opaque.revision() > sync.revision() {
                return Err(EncodingError::new(
                    "Contact revision exceeds snapshot revision",
                ));
            }
            let DecodedContact {
                contact,
                session,
                channel,
            } = self.decode_contact(opaque)?;
            let id = *contact.id();
            if state.contacts.contains_key(&id) {
                return Err(EncodingError::new("Snapshot contains duplicate contacts"));
            }
            let is_channel = channel.is_some();
            if let Some(session) = session {
                state
                    .sessions
                    .insert(id, self.session_context(id, session, is_channel));
            }
            if let Some(channel) = channel {
                state.channels.insert(id, channel);
            }
            state.contacts.insert(id, Box::new(contact));
        }
        state.revision = sync.revision();
        Ok(())
    }

    pub(super) fn superseded_mutations(mutations: &[ContactMutation]) -> Vec<bool> {
        let mut superseded = vec![false; mutations.len()];
        let mut touched = HashSet::new();
        let mut cleared = false;
        for (index, mutation) in mutations.iter().enumerate().rev() {
            match mutation.data() {
                Some(MutationData::Add(opaque) | MutationData::Update(opaque)) => {
                    superseded[index] = cleared || !touched.insert(*opaque.id());
                }
                Some(MutationData::Remove(ids)) => touched.extend(ids.iter().copied()),
                None | Some(MutationData::Clear) => cleared = true,
            }
        }
        superseded
    }

    pub(super) fn apply_delta(&self, sync: &ContactSync, state: &mut ContactState) -> Result<()> {
        let original_revision = self.contacts_revision.get();
        let superseded = Self::superseded_mutations(sync.mutations());
        for (index, mutation) in sync.mutations().iter().enumerate() {
            if mutation.revision() < 0 {
                return Err(EncodingError::new("Contact mutation revision is negative"));
            }
            if mutation.revision() < state.revision {
                continue;
            }
            if mutation.revision() > state.revision {
                self.contact_sync_needed.set(true);
                return Err(StateError::new("Contact delta has a revision gap"));
            }
            let next = state
                .revision
                .checked_add(1)
                .ok_or_else(|| EncodingError::new("Contact revision is exhausted"))?;

            match mutation.data() {
                Some(MutationData::Add(opaque) | MutationData::Update(opaque)) => {
                    if opaque.revision() != next {
                        return Err(EncodingError::new(
                            "Contact mutation revision is inconsistent",
                        ));
                    }
                    if superseded[index] {
                        state.revision = next;
                        continue;
                    }
                    let DecodedContact {
                        contact,
                        session,
                        channel,
                    } = self.decode_contact(opaque)?;
                    let id = *contact.id();
                    state.sessions.remove(&id);
                    let is_channel = channel.is_some();
                    if let Some(session) = session {
                        state
                            .sessions
                            .insert(id, self.session_context(id, session, is_channel));
                    }
                    state.channels.remove(&id);
                    if let Some(channel) = channel {
                        state.channels.insert(id, channel);
                    }
                    state.contacts.insert(id, Box::new(contact));
                }
                Some(MutationData::Remove(ids)) => {
                    for id in ids {
                        state.contacts.remove(&id);
                        state.sessions.remove(&id);
                        state.channels.remove(id);
                    }
                }
                None | Some(MutationData::Clear) => {
                    state.contacts.clear();
                    state.sessions.clear();
                    state.channels.clear();
                }
            }
            state.revision = next;
        }
        if state.revision < sync.revision()
            || (state.revision > sync.revision() && state.revision > original_revision)
        {
            return Err(EncodingError::new(
                "Contact delta final revision is inconsistent",
            ));
        }
        Ok(())
    }

    pub(super) fn commit_contact_state(
        &self,
        previous: HashMap<Id, Contact>,
        state: ContactState,
    ) -> Result<()> {
        let removed: Vec<_> = previous
            .keys()
            .filter(|id| !state.contacts.contains_key(id))
            .copied()
            .collect();
        let added: Vec<Contact> = state
            .contacts
            .values()
            .filter(|contact| !previous.contains_key(contact.id()))
            .cloned()
            .collect();
        let updated: Vec<Contact> = state
            .contacts
            .values()
            .filter(|contact| Self::contact_changed(previous.get(contact.id()), contact))
            .cloned()
            .collect();

        for id in &removed {
            let _ = self.repository.borrow_mut().remove_contact_locally(id);
        }
        for (id, contact) in &state.contacts {
            if let Some(channel) = state.channels.get(id) {
                let photon = channel.photon_contact();
                let session_key = match photon.session_key() {
                    Some(key) => key.to_vec(),
                    None => match state.sessions.get(id) {
                        Some(session) => self
                            .user_identity
                            .encrypt_into(self.user_id(), session.private_key())?,
                        None => Vec::new(),
                    },
                };
                let boxed: Channel = Box::new(channel.clone());
                self.repository
                    .borrow_mut()
                    .store_channel(state.revision, &boxed, &session_key)?;
                continue;
            }
            let mut data = ContactData::from(contact);
            data.set_revision(state.revision);
            if let Some(session) = state.sessions.get(id) {
                data.set_session_key(
                    self.user_identity
                        .encrypt_into(self.user_id(), session.private_key())?,
                );
            }
            let session_key = data.session_key().map(|key| key.to_vec());
            let photon = PhotonContact::try_from(data)?;
            self.repository.borrow_mut().put_contact(
                state.revision,
                &photon,
                session_key.as_deref(),
            )?;
        }

        *self.blocked_contacts.lock().unwrap() = state
            .contacts
            .values()
            .filter(|contact| contact.is_blocked())
            .map(|contact| *contact.id())
            .collect();
        *self.session_contexts.lock().unwrap() = state.sessions;
        self.contacts_revision.set(state.revision);

        if !removed.is_empty() {
            self.contact_listener.on_contacts_removed(&removed);
        }
        for contact in added {
            self.contact_listener.on_contact_added(&contact);
        }
        if !updated.is_empty() {
            self.contact_listener.on_contacts_updated(&updated);
        }
        Ok(())
    }

    pub(super) fn contact_changed(old: Option<&Contact>, new: &Contact) -> bool {
        let Some(old) = old else {
            return false;
        };
        old.revision() != new.revision()
            || old.updated_at() != new.updated_at()
            || old.is_blocked() != new.is_blocked()
            || old.is_muted() != new.is_muted()
            || old.name() != new.name()
            || old.remark() != new.remark()
            || old.tags() != new.tags()
            || old.contact_type() != new.contact_type()
    }

    fn process_incoming_handshake(
        &self,
        message: PhotonMessage,
        from: &Id
    ) -> Result<()> {
        let handshake = Handshake::deserialize(&message.payload_bytes)?;
        match handshake.body {
            HandshakeType::FriendRequest(hello) => {
                let friend_id = *from;
                if handshake.timestamp < 0 {
                    return Ok(());
                }
                if let Some(contact) = self.repository.borrow_mut().contact(&friend_id).ok().flatten() {
                    if contact.is_blocked()
                        || contact.contact_type() == ContactType::Friend
                        || contact.contact_type() == ContactType::Channel
                    {
                        return Ok(());
                    }
                }
                if self.friend_request(&friend_id).is_some_and(|request| {
                    request.is_accepted() || request.created_at() >= handshake.timestamp
                }) {
                    debug!("Ignoring duplicate or stale friend request from {friend_id}");
                    return Ok(());
                }
                let request = PhotonFriendRequest::create(
                    friend_id,
                    friend_id,
                    hello.clone(),
                    handshake.timestamp,
                );
                self.put_friend_request(&request)?;
                self.friend_request_listener
                    .on_friend_request(&friend_id, hello.as_deref());
                Ok(())
            }
            HandshakeType::FriendRequestAccept(_) => Ok(()),
        }
    }

    async fn accept_friend_handshake(
        &self,
        friend_id: Id,
        session_key: Vec<u8>,
        timestamp: i64,
        is_inbox: bool,
    ) {
        let _request = self.requests.lock().await;

        if self.friend_request(&friend_id).is_some_and(|request| request.is_accepted()) {
            debug!("Ignoring duplicate friend request acceptance from {friend_id}");
            return;
        }
        let initiator_id = if is_inbox { *self.user_identity.id() } else { friend_id };
        let request = match self.pending_friend_request(&friend_id, &initiator_id) {
            Ok(request) => request,
            Err(error) => {
                warn!("Failed to find pending friend request for {friend_id}: {error}");
                return;
            }
        };
        let created = request
            .created()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0);
        if timestamp < created {
            warn!("Friend request acceptance predates the request");
            return;
        }
        let session_identity = match CryptoIdentity::try_from(session_key.as_slice()) {
            Ok(identity) => identity,
            Err(_) => return,
        };
        if let Err(error) = self.store_friend_contact(&friend_id, &session_identity).await {
            warn!("Failed to store friend contact: {error}");
            return;
        }
        self.session_contexts
            .lock()
            .unwrap()
            .entry(friend_id)
            .or_insert_with(|| self.session_context(friend_id, session_identity, false));
        if let Some(mut request) = self.friend_request(&friend_id) {
            if !request.is_accepted() {
                request.accept(timestamp);
                if let Err(error) = self.put_friend_request(&request) {
                    warn!("Persisting accepted friend request failed: {error}");
                }
            }
        }
        self.friend_request_listener.on_friend_request_accepted(&friend_id);
    }

    async fn process_outgoing_handshake(&self, message: PhotonMessage, from: &Id) -> Result<()> {
        if message.is_originated(self.device_id()) {
            trace!("The handshake {} to {} is redundant (or originated from self), ignoring it.",
                MessageOps::id(&message), from);
            return Ok(());
        }

        let handshake = Handshake::deserialize(&message.payload_bytes)?;
        match handshake.body {
            HandshakeType::FriendRequest(hello) => {
                trace!("Friend request sent to {}", message.recipient());
                let request = PhotonFriendRequest::create(
                    *message.recipient(),
                    *self.user_identity.id(),
                    hello,
                    handshake.timestamp,
                );
                self.put_friend_request(&request)?;
                Ok(())
            }
            HandshakeType::FriendRequestAccept(_session_key) => {
                trace!("Accept friend request from {}", message.recipient());
                let user_id = *message.recipient();
                if let Some(mut request) = self.friend_request(&user_id) {
                    if !request.is_accepted()
                        && request.initiator_id() == self.user_identity.id()
                        && handshake.timestamp >= request.created_at()
                    {
                        request.accept(handshake.timestamp);
                        self.put_friend_request(&request)?;
                    }
                }
                Ok(())
            }
        }
    }

    pub(super) fn pending_friend_request(&self, user_id: &Id, initiator_id: &Id) -> Result<FriendRequest> {
        let request = self
            .friend_request(user_id)
            .ok_or_else(|| ArgumentError::new(format!("No friend request found for {user_id}")))?;
        if self
            .repository
            .borrow_mut()
            .contact(user_id)
            .ok()
            .flatten()
            .is_some_and(|contact| {
                contact.is_blocked() || contact.contact_type() == ContactType::Channel
            })
        {
            return Err(ArgumentError::new(
                "Cannot accept a friend request from a blocked user or channel",
            ));
        }
        if request.initiator_id() != initiator_id {
            return Err(ArgumentError::new(
                "Friend request has an unexpected initiator",
            ));
        }
        if request.is_accepted() {
            return Err(ArgumentError::new(
                "Friend request has already been accepted",
            ));
        }
        if request.is_expired() {
            return Err(ArgumentError::new("Friend request has expired"));
        }
        Ok(Box::new(request.clone()))
    }

    /// Records a friend locally, including their session key.
    pub(super) async fn store_friend_contact(&self, user_id: &Id, session: &CryptoIdentity) -> Result<()> {
        if self.contact(user_id).await
            .is_some_and(|contact| contact.contact_type() == ContactType::Friend)
        {
            return Ok(());
        }
        let revision = self.contacts_revision.get();
        let mut data = ContactData::new(
            *user_id,
            ContactType::Friend as u8,
            Self::current_timestamp()?,
        );
        data.set_session_key(self.user_identity.encrypt_into(
            self.user_id(),
            session.signature_key().private_key().as_ref(),
        )?);
        data.revision = revision;
        let session_key = data.session_key().map(|key| key.to_vec());
        let mutation = ContactMutation::add(revision, data.encode_into(&self.user_identity)?);
        let confirmed = self
            .apply_contact_mutation(mutation, revision, "Friend contact revision is outdated")
            .await?;
        let contact = data.contact(confirmed)?;
        self.persist_contact(&contact, session_key.as_deref())?;
        Ok(())
    }

    async fn conversation_or_create(&self, id: &Id) -> Result<PhotonConversation> {
        if let Some(conversation) = self.conversation(id).await {
            return Ok(conversation);
        }
        let contact = self
            .contact(id)
            .await
            .ok_or_else(|| StateError::new(format!("No contact found for {id}")))?;
        Ok(PhotonConversation::new(Box::new(contact) as Contact))
    }

    async fn process_incoming_content_message(
        &self,
        mut message: PhotonMessage,
        from: &Id,
    ) -> Result<()> {
        if from == self.user_id() {
            return Err(StateError::new("Received a message from self").into());
        }

        let content = match PhotonContent::parse(&message.payload_bytes) {
            Ok(content) => content,
            Err(error) => {
                warn!("Malformed incoming content: {error}");
                return Err(error);
            }
        };
        let content_message = message.set_content(content);
        message.set_from(*from);

        if let Err(error) = self.repository.borrow_mut().put_message(&mut message) {
            error!(
                "Failed to persist incoming message {}: {error}",
                MessageOps::id(&message)
            );
        }

        let Some(conversation_id) = message.conversation_id().copied() else {
            return Err(StateError::new("Conversation ID is missing").into());
        };

        match self.conversation_or_create(&conversation_id).await {
            Ok(mut conversation) => {
                if let Err(error) = conversation.update(content_message.clone()) {
                    warn!("Failed to update conversation {conversation_id}: {error}");
                }
                let _ = self.repository.borrow_mut().put_conversation(conversation);
            }
            Err(error) => {
                warn!("Failed to get or create conversation {conversation_id}: {error}");
            }
        }

        self.message_listener.on_message(&content_message);
        Ok(())
    }

    fn process_outgoing_content_message(&self, mut message: PhotonMessage, from: Id) {
        let contact_id = message.conversation_id().copied().unwrap_or(*message.recipient());

        let content = match PhotonContent::parse(&message.payload_bytes) {
            Ok(content) => content,
            Err(error) => {
                warn!("Malformed outgoing content: {error}");
                return;
            }
        };
        let content_message = message.set_content(content);
        message.set_from(from);
        message.set_sent(now_millis() as i64);

        if message.is_originated(self.device_id()) {
            trace!(
                "Message {} sent to {} originated from this device",
                MessageOps::id(&message),
                contact_id
            );
            self.message_listener.on_sent(&content_message);
            return;
        }

        trace!(
            "Message {} sent to {} originated from another device",
            MessageOps::id(&message),
            contact_id
        );
        if let Err(error) = self.repository.borrow_mut().put_message(&mut message) {
            warn!("Failed to persist outgoing message: {error}");
        }
        self.message_listener.on_sent(&content_message);
    }

    fn current_timestamp() -> Result<i64> {
        Ok(now_millis() as i64)
    }

    pub(super) fn message_id(device_id: &Id, timestamp: i64) -> Result<Id> {
        let mut digest = Sha256::new();
        digest.update(device_id.as_bytes());
        digest.update(timestamp.to_be_bytes());

        let hash = digest.finalize();
        Id::try_from_bytes(hash.as_slice())
            .map_err(|error| EncodingError::new(error.to_string()).into())
    }

    pub(super) fn notify_connection(&self, callback: impl Fn(&dyn ConnectionListener)) {
        callback(self.connection_listener.as_ref());
    }

    /// Asks the service for everything that changed since our revision.
    pub(super) async fn sync_contacts(&self) -> Result<()> {
        // 1. Validate: nothing to check, the sync starts from our revision.
        let revision = self.contacts_revision.get();

        // 2. Build the request.
        let request = RPCRequest::contact_sync(0, revision);

        // 3. Send it to the home peer and 4. decode the delta it reports.
        let result = self.send_rpccall(self.peer_id(), request).await?;
        let response::Value::ContactSync(sync) = result else {
            return Err(EncodingError::new("RPC result is not a contact sync").into());
        };

        // 5. Apply the delta to the local state.
        self.apply_contact_sync(&sync).await
    }

    /// Sends a contact mutation document and adopts the revision it reports.
    ///
    /// `minimum` is the revision the caller needs to see: plain mutations only
    /// require the current one, while `update_contact` insists on the revision
    /// it computed so that a concurrent change cannot silently win.
    pub(super) async fn commit_contact_mutation(
        &self,
        mutation: ContactMutation,
        minimum: i32,
        outdated: &str,
    ) -> Result<i32> {
        let request = RPCRequest::contact_mutate(0, mutation);
        let result = self.send_rpccall(self.peer_id(), request).await?;
        let response::Value::ContactMutate(revision) = result else {
            return Err(EncodingError::new("RPC result is not a contact revision").into());
        };
        if revision < minimum || revision < self.contacts_revision.get() {
            return Err(StateError::new(outdated));
        }
        self.contacts_revision.set(revision);
        Ok(revision)
    }

    /// Encodes and sends a [`ContactMutation`].
    pub(super) async fn apply_contact_mutation(
        &self,
        mutation: ContactMutation,
        minimum: i32,
        outdated: &str,
    ) -> Result<i32> {
        self.commit_contact_mutation(mutation, minimum, outdated)
            .await
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
