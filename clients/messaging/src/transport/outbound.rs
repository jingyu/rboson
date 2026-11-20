use super::prelude::*;
use super::mqtt;

pub(super) const FIELD_SESSION_KEY: &str = "sk";
pub(super) const FIELD_OWNER: &str = "o";
pub(super) const FIELD_PERMISSION: &str = "p";
pub(super) const FIELD_NOTICE: &str = "nt";
pub(super) const FIELD_ANNOUNCED: &str = "a";

impl RpcServer {
    /// Reads a page of history. Not implemented yet.
    pub(crate) async fn get_messages(
        &self,
        conversation_id: &Id,
        until: Option<i64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Message>> {
        let messages = self.repository.borrow_mut().messages_before(
            conversation_id,
            until.unwrap_or(i64::MAX),
            limit,
            offset,
        )?;
        Ok(messages.into_iter().map(|message| Box::new(message) as Message).collect())
    }

    /// Reads history in a timestamp range. Not implemented yet.
    pub(crate) async fn get_messages_in_range(
        &self,
        conversation_id: &Id,
        begin: i64,
        end: i64,
    ) -> Result<Vec<Message>> {
        let messages = self.repository
            .borrow_mut()
            .messages_in_range(conversation_id, begin, end)?;
        Ok(messages.into_iter().map(|message| Box::new(message) as Message).collect())
    }

    /// Removes a message. Not implemented yet.
    pub(crate) async fn _remove_message(&self, message_id: i64) -> Result<()> {
        self.repository.borrow_mut().remove_message(message_id)?;
        Ok(())
    }

    /// Removes messages by id. Not implemented yet.
    pub(crate) async fn remove_messages_by_ids(&self, message_ids: &[i64]) -> Result<()> {
        self.repository.borrow_mut().remove_messages(message_ids)?;
        Ok(())
    }

    /// Clears a conversation's history. Not implemented yet.
    pub(crate) async fn remove_messages_in_conversation(
        &self,
        conversation_id: &Id,
    ) -> Result<()> {
        self.repository
            .borrow_mut()
            .remove_messages_in_conversation(conversation_id)?;
        Ok(())
    }

    pub(crate) async fn get_sessions(&self) -> Result<Vec<SessionInfo>> {
        let request = RPCRequest::list_sessions(0);

        let result = self.send_rpccall(self.peer_id(), request).await?;
        let ResponseParams::SessionList(sessions) = result else {
            return Err(EncodingError::new("RPC result is not a session list").into());
        };

        Ok(sessions)
    }

    pub(crate) async fn revoke_session(&self, device_id: &Id) -> Result<()> {
        assert!(device_id != self.device_id());

        let request = RPCRequest::revoke_session(0, *device_id);
        let _ = self.send_rpccall(self.peer_id(), request).await?;
        Ok(())
    }

    pub(crate) async fn send_friend_request(
        &self,
        user_id: &Id,
        hello: Option<String>
    ) -> Result<()> {
        assert!(
            user_id != self.user_identity.id(),
            "Cannot send a friend request to yourself"
        );

        info!("Sending friend request to {user_id} with hello: {:?}", hello);

        let userid = *user_id;
        let timestamp = self.origin_timestamp();
        let handshake = Handshake::friend_request(hello.clone(), timestamp);
        let payload = handshake.serialize()?;
        let fr = PhotonFriendRequest::create(
            userid,
            *self.user_identity.id(),
            hello,
            timestamp,
        );
        self.put_friend_request(&fr)?;

        let mut message = PhotonMessage::new(
            MESSAGE_VERSION as i32,
            Self::message_id(self.device_identity.id(), timestamp)?,
            userid,
            HANDSHAKE_MESSAGE as i32,
            None,
            timestamp,
            Value::Bytes(payload.clone()),
        );
        message.payload_bytes = payload;
        if let Err(error) = self.send_message_internal(message).await {
            error!("Failed to send friend request to {userid}: {error}");
            let _ = self.remove_friend_request(&userid);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) async fn accept_friend_request(&self, user_id: &Id) -> Result<()> {
        let Some(fr) = self.friend_request(user_id) else {
            return Err(StateError::new(
                format!("No friend request found for {user_id}")
            ));
        };
        if fr.initiator_id() == self.user_id() {
            return Err(StateError::new(
                "Can not accept your own friend request"
            ));
        }
        if fr.is_accepted() {
            return Err(StateError::new(
                "Friend request has already been accepted",
            ));
        }
        if fr.is_expired() {
            return Err(StateError::new("Friend request has expired"));
        }

        if self
            .contact(user_id)
            .await
            .is_some_and(|contact| contact.is_blocked() || contact.contact_type() == ContactType::Channel)
        {
            return Err(StateError::new(
                "Cannot accept a friend request from a blocked user or channel",
            ));
        }

        let key = signature::KeyPair::random();
        let session_key = key.private_key().as_bytes().to_vec();
        let session_identity = CryptoIdentity::from(key);
        let userid = *user_id;
        let timestamp = self.origin_timestamp();
        let handshake = Handshake::friend_request_accept(session_key, timestamp);
        let payload = handshake.serialize()?;
        let mut message = PhotonMessage::new(
            MESSAGE_VERSION as i32,
            Self::message_id(self.device_identity.id(), timestamp)?,
            userid,
            HANDSHAKE_MESSAGE as i32,
            None,
            timestamp,
            Value::Bytes(payload.clone()),
        );
        message.payload_bytes = payload;

        if let Err(error) = self.send_message_internal(message).await {
            error!("Failed to send friend request accept to {userid}: {error}");
            return Err(error.into());
        }
        if timestamp < fr.created_at() {
            return Err(StateError::new("Friend request changed while accepting").into());
        }

        self.store_friend_contact(&userid, &session_identity).await?;

        self.session_contexts.lock().unwrap().insert(
            userid,
            self.session_context(userid, session_identity, false),
        );
        self.on_friend_request_accepted1(userid, timestamp, false).await;
        Ok(())
    }

    pub(super) async fn on_friend_request_accepted1(&self, user_id: Id, timestamp: i64, notify: bool) {
        if timestamp < 0 {
            warn!("Ignoring friend request acceptance from {user_id} with a negative timestamp");
            return;
        }

        let Some(mut request) = self.friend_request(&user_id) else {
            return;
        };

        if request.is_accepted() || request.is_expired() {
            return;
        }
        let initiator_id = if notify {
            self.user_identity.id()
        } else {
            &user_id
        };

        if request.initiator_id() != initiator_id || timestamp < request.created_at() {
            warn!("Ignoring friend request acceptance from {user_id} that does not match the pending request");
            return;
        }

        request.accept(timestamp);
        if let Err(error) = self.put_friend_request(&request) {
            warn!("Persisting accepted friend request failed: {error}");
        }

        if self
            .contact(&user_id)
            .await
            .is_some_and(|contact| contact.contact_type() == ContactType::Friend)
        {
            if notify {
                self.friend_request_listener
                    .on_friend_request_accepted(&user_id);
            }
            return;
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0);
        let mut contact = PhotonContact::new(user_id, ContactType::Friend, now_ms);
        contact.set_revision(self.contacts_revision.get());
        if let Err(error) = self.put_contact(&contact).await {
            warn!("Persisting friend contact failed: {error}");
        }
        if notify {
            self.friend_request_listener
                .on_friend_request_accepted(&user_id);
        }
        let contact: Contact = Box::new(contact);
        self.contact_listener.on_contact_added(&contact);
    }

    /// Registers an existing friend, given their session key, and syncs the
    /// new contact to the user's other devices.
    pub(crate) async fn add_friend(
        &self,
        user_id: &Id,
        session_key: Vec<u8>,
        remark: Option<String>,
    ) -> Result<()> {

        assert!(
            user_id != self.user_id(),
            "Cannot add yourself as a friend",
        );

        // 1. Validate: the session key is well-formed and the revision can advance.
        let session_identity = CryptoIdentity::try_from(session_key.as_slice())?;
        let revision = self.contacts_revision.get();
        let next_revision = revision
            .checked_add(1)
            .ok_or_else(|| StateError::new("Contact revision is exhausted"))?;

        // 2. Build the request.
        let now_ms = SystemTime::now();
        let mut data = ContactData::new(
            *user_id,
            ContactType::Friend as u8,
            boson_api::as_ms!(now_ms) as i64,
        );
        data.remark = remark;
        data.revision = next_revision;
        data.set_session_key(
            self.user_identity
                .encrypt_into(self.user_id(), &session_key)?,
        );
        let opaque = data.encode_into(&self.user_identity)?;
        let mutation = ContactMutation::add(revision, opaque);
        let request = RPCRequest::contact_mutate(0, mutation);

        // 3. Send it to the home peer and 4. decode the revision it reports.
        let result = self.send_rpccall(self.peer_id(), request).await?;
        let confirmed = match result {
            ResponseParams::ContactMutate(confirmed) => confirmed,
            _ => return Err(EncodingError::new("RPC result is not a contact revision").into()),
        };
        if confirmed < next_revision || confirmed < self.contacts_revision.get() {
            return Err(StateError::new("Contact addition revision is outdated"));
        }
        self.contacts_revision.set(confirmed);

        // 5. Apply the confirmed change to the local state.
        let contact = data.contact(confirmed)?;
        self.session_contexts.lock().unwrap().insert(
            *user_id,
            self.session_context(*user_id, session_identity, false),
        );
        self.put_contact(&contact).await?;

        // 6. Notify the application.
        self.contact_listener.on_contact_added(&(Box::new(contact) as Contact));
        Ok(())
    }

    /// Blocks a user by marking their contact as blocked and syncing the change.
    pub(crate) async fn block_user(&self, user_id: &Id) -> Result<Contact> {
        assert!(
            user_id != self.user_id(),
            "Cannot block yourself",
        );

        // 1. Validate and build the contact to sync.
        let revision = self.contacts_revision.get();
        let now = boson_api::as_ms!(SystemTime::now()) as i64;
        let (data, existing) = match self.contact(user_id).await {
            Some(contact) => {
                if contact.contact_type() == ContactType::Channel {
                    return Err(ArgumentError::new(format!(
                        "Not a user: {user_id} is a channel"
                    ))
                    .into());
                }
                if contact.is_blocked() {
                    return Ok(Box::new(contact) as Contact);
                }
                let mut data = ContactData::from(&contact);
                data.set_blocked(true);
                data.set_updated(now.max(contact.updated_at()));
                data.set_revision(revision);
                (data, true)
            }
            None => {
                // Not a contact: an AUTO contact carries the blocked state.
                let mut data = ContactData::new(*user_id, ContactType::Auto as u8, now);
                data.set_blocked(true);
                data.set_updated(now);
                data.set_revision(revision);
                (data, false)
            }
        };

        // 2. Build and send the contact mutation.
        let opaque = data.encode_into(&self.user_identity)?;
        let mutation = if existing {
            ContactMutation::update(revision, opaque)
        } else {
            ContactMutation::add(revision, opaque)
        };
        let request = RPCRequest::contact_mutate(0, mutation);

        let result = self.send_rpccall(self.peer_id(), request).await?;
        let confirmed = match result {
            ResponseParams::ContactMutate(confirmed) => confirmed,
            _ => return Err(EncodingError::new("RPC result is not a contact revision").into()),
        };
        if confirmed < revision || confirmed < self.contacts_revision.get() {
            return Err(StateError::new("Contact block revision is outdated"));
        }
        self.contacts_revision.set(confirmed);

        // 3. Apply the confirmed change to the local state.
        let blocked = data.contact(confirmed)?;
        self.put_contact(&blocked).await?;
        self.blocked_contacts.lock().unwrap().insert(*user_id);

        Ok(Box::new(blocked) as Contact)
    }

    pub(crate) async fn create_channel(
        &self,
        permission: Permission,
        name: String,
        notice: Option<String>,
        announce: bool,
    ) -> Result<Channel> {
        let identity = CryptoIdentity::random();
        let session_id = identity.id();

        let session_key = identity.signature_key().private_key().as_bytes();
        let encrypted_key = self
            .user_identity
            .encrypt_into(self.user_id(), session_key)?;

        let new_channel_info = NewChannelInfo::new(
            *session_id,
            encrypted_key,
            permission,
            Some(name.clone()),
            notice.clone(),
            announce,
        );
        let request = RPCRequest::create_channel(0, new_channel_info);

        let result = self.send_rpccall(self.peer_id(), request).await?;
        let ResponseParams::ChannelCreate(channel_info) = result else {
            return Err(EncodingError::new("RPC result is not channel info").into());
        };

        let returned_session = self.session_context(*channel_info.channel_id(), identity, true);
        let channel = Box::new(PhotonChannel::try_from(&channel_info)?) as Box<dyn ChannelHandler>;
        if channel.owner() != self.user_id() {
            return Err(EncodingError::new(
                "Created channel owner or session does not match",
            ));
        }

        self.store_channel(channel.clone(), returned_session)
            .await?;

        self.channel_listener.on_channel_created(&channel);
        Ok(channel)
    }

    pub(crate) async fn delete_channel(&self, channel_id: &Id) -> Result<()> {
        let Some(channel) = self.channel(channel_id).map(|v| Box::new(v) as Channel) else {
            return Err(StateError::new(format!("Channel {channel_id} does not exist")).into());
        };
        if channel.owner() != self.user_id() {
            return Err(StateError::new("Only the owner can delete the channel"));
        }

        let request = RPCRequest::delete_channel(0);
        let result = self.send_rpccall(channel_id, request).await?;
        let _ = result;

        self.remove_channel_contact(channel_id).await?;
        self.channel_listener.on_channel_deleted(&channel);
        Ok(())
    }

    pub(crate) async fn join_channel(&self, ticket: InviteTicket) -> Result<Channel> {
        assert!(ticket.is_genuine());
        assert!(!ticket.is_expired());
        assert!(ticket.invitee().is_some_and(|id| id == self.user_id()));

        if self
            .channel(ticket.channel_id())
            .is_some_and(|channel| channel.has_member(self.user_id()))
        {
            return Err(StateError::new("Already joined the channel").into());
        }

        let key = if ticket.is_named_ticket() {
            self.user_identity
                .decrypt_into(ticket.inviter(), ticket.session_key())?
        } else {
            ticket.session_key().to_vec()
        };

        let session = CryptoIdentity::try_from(key.as_slice())?;
        if session.id() != ticket.session_id() {
            return Err(ArgumentError::new(
                "Invitation session key does not match session ID",
            ));
        }

        let key = self.user_identity.encrypt_into(self.user_id(), &key)?;
        let params = JoinChannel::new(
            *ticket.channel_id(),
            *ticket.session_id(),
            *ticket.inviter(),
            ticket.expiration_ms(),
            ticket.signature().to_vec(),
            key,
            ticket.invitee().copied(),
        );
        let request = RPCRequest::join_channel(0, params);

        let result = self.send_rpccall(ticket.channel_id(), request).await?;
        let ResponseParams::ChannelJoin(channel_info) = result else {
            return Err(EncodingError::new("RPC result is not channel info").into());
        };
        let returned_session = self.session_context(*channel_info.channel_id(), session.clone(), true);
        let channel = Box::new(PhotonChannel::try_from(&channel_info)?) as Box<dyn ChannelHandler>;

        if channel.id() != ticket.channel_id()
            || channel.session_id() != session.id()
            || !channel.has_member(self.user_id())
        {
            return Err(EncodingError::new(
                "Joined channel does not match invitation or membership",
            )
            .into());
        }

        self.store_channel(channel.clone(), returned_session)
            .await?;

        self.channel_listener.on_joined_channel(&channel);
        Ok(channel)
    }

    pub(crate) async fn leave_channel(&self, channel_id: &Id) -> Result<()> {
        let Some(channel) = self.channel(channel_id).map(|v| Box::new(v) as Channel) else {
            return Err(StateError::new("Channel not found").into());
        };
        if channel.owner() == self.user_id() {
            return Err(StateError::new("The owner cannot leave the channel"));
        }

        let request = RPCRequest::leave_channel(0);
        let result = self.send_rpccall(channel_id, request).await?;
        let _ = result;

        self.remove_channel_contact(channel_id).await?;

        self.channel_listener.on_left_channel(&channel);
        Ok(())
    }

    pub(crate) async fn create_invite_ticket(
        &self,
        channel_id: &Id,
        invitee: Option<Id>,
    ) -> Result<InviteTicket> {
        let request = RPCRequest::get_channel_info(0);
        let result = self.send_rpccall(channel_id, request).await?;
        let ResponseParams::ChannelInfo(info) = result else {
            return Err(EncodingError::new("RPC result is not channel info").into());
        };
        let channel = PhotonChannel::try_from(&info)?;
        if channel.id() != channel_id {
            return Err(EncodingError::new("Channel info has an unexpected ID"));
        }
        self.put_channel(Self::to_photon_channel(channel.as_ref())?)?;
        let member = channel
            .member(self.user_id())
            .ok_or_else(|| StateError::new("Not a member of the channel"))?;
        let allowed = match channel.permission() {
            Permission::Public | Permission::MemberInvite => !member.is_banned(),
            Permission::ModeratorInvite => member.is_owner() || member.is_moderator(),
            Permission::OwnerInvite => member.is_owner(),
        };
        if !allowed {
            return Err(
                StateError::new("Insufficient permission to invite channel members").into(),
            );
        }
        if invitee.is_some_and(|id| channel.has_member(&id)) {
            return Err(ArgumentError::new("The invitee is already a channel member").into());
        }
        let session = self
            .session_contexts
            .lock()
            .unwrap()
            .get(channel_id)
            .cloned()
            .ok_or_else(|| StateError::new("Channel session key is missing"))?;
        let key = session.private_key().to_vec();
        let key = match invitee {
            Some(id) => self.user_identity.encrypt_into(&id, &key)?,
            None => key,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| StateError::new(format!("System clock error: {error}")))?;
        let expiration = u64::try_from(now.as_millis())
            .ok()
            .and_then(|now| now.checked_add(InviteTicket::DEFAULT_EXPIRATION_MS))
            .ok_or_else(|| StateError::new("Invitation expiration is out of range"))?;
        InviteTicket::create(
            &self.user_identity,
            *channel_id,
            *channel.session_id(),
            invitee,
            expiration,
            key,
        )
        .map_err(|e| e.into())
    }

    async fn store_channel(&self, mut channel: Channel, session: SessionContext) -> Result<()> {
        let key = self
            .user_identity
            .encrypt_into(self.user_id(), session.private_key())?;
        let mut data = ContactData::new(
            *channel.id(),
            ContactType::Channel as u8,
            channel.created_at(),
        );
        data.set_session_key(key.clone());
        data.name = channel.name().map(ToString::to_string);
        data.updated_at = channel.updated_at();
        let Value::Map(mut document) = to_cbor(&data, "channel contact")? else {
            return Err(EncodingError::new("Channel contact is not a map"));
        };
        Self::insert_channel_fields(&mut document, &channel, key.clone());
        let document = to_cbor_bytes(&Value::Map(document), "channel contact")?;
        let document = self.user_identity.encrypt_into(self.user_id(), &document)?;

        let revision = self.contacts_revision.get();
        let mutation = ContactMutation::add(
            revision,
            OpaqueContact::new(*channel.id(), revision, Value::Bytes(document)),
        );
        let revision = self
            .commit_contact_mutation(mutation, revision, "Channel contact revision is outdated")
            .await?;
        channel.set_contact_revision(revision);
        self.session_contexts
            .lock()
            .unwrap()
            .insert(*channel.id(), session);
        let contact = Self::to_photon_contact_ops(channel.contact_box().as_ref())?;
        self.contact_listener.on_contact_added(&(Box::new(contact) as Contact));
        self.repository.borrow_mut().store_channel(revision, &channel, &key)?;
        Ok(())
    }

    async fn remove_channel_contact(&self, id: &Id) -> Result<()> {
        let revision = self.contacts_revision.get();
        let mutation = ContactMutation::remove(revision, vec![*id]);
        self.commit_contact_mutation(mutation, revision, "Channel contact revision is outdated")
            .await?;

                self.remove_contact(id).await;

        self.contact_listener.on_contacts_removed(&[*id]);
        Ok(())
    }

    pub(crate) async fn transfer_channel_ownership(
        &self,
        channel_id: &Id,
        new_owner: Id,
    ) -> Result<()> {
        let Some(mut channel) = self.channel(channel_id) else {
            return Err(StateError::new("Channel not found").into());
        };
        if channel.owner() != self.user_id() {
            return Err(StateError::new("Only the channel owner can transfer ownership"));
        }

        let target = channel
            .member(&new_owner)
            .ok_or_else(|| StateError::new("The new owner is not a member of the channel"))?;
        if target.is_banned() {
            return Err(StateError::new("The new owner is banned from the channel"));
        }
        let old_owner = *channel.owner();
        if new_owner == old_owner {
            return Err(ArgumentError::new("The new owner is already the channel owner").into());
        }

        // 2. Build the request.
        let request = RPCRequest::transfer_channel_ownership(0, new_owner);

        // 3. Send it and 4. check the reply carries no result.
        let result = self.send_rpccall(channel_id, request).await?;
        let _ = result;

        // 5. Apply the change: the new owner takes over, the former owner keeps moderating.
        channel.set_owner(new_owner);
        channel.update_member_roles(&[new_owner], Role::Owner);
        channel.update_member_roles(&[old_owner], Role::Moderator);
        self.put_channel(channel)?;
        Ok(())
    }

    pub(crate) async fn rotate_channel_session_key(&self, channel_id: &Id) -> Result<()> {
        let Some(mut channel) = self.channel(channel_id) else {
            return Err(StateError::new("Channel not found").into());
        };
        if channel.owner() != self.user_id() {
            return Err(StateError::new("Only the channel owner can rotate the session key"));
        }

        let keypair = signature::KeyPair::random();
        let encrypted_key = {
            let mut sessions = self.session_contexts.lock().unwrap();
            let current_session = sessions
                .get_mut(channel_id)
                .ok_or_else(|| StateError::new("Channel session key is missing"))?;
            if current_session.session_id() != channel.session_id() {
                return Err(StateError::new(
                    "Channel session key does not match the channel",
                ));
            }
            current_session
                .tx_crypto_context()?
                .encrypt_into(keypair.private_key().as_ref())?
        };

        let session = CryptoIdentity::from(keypair.clone());
        let rotation = ChannelSessionKeyRotation::new(*session.id(), encrypted_key);
        let request = RPCRequest::rotate_channel_session_key(0, rotation);

        let result = self.send_rpccall(channel_id, request).await?;
        let _ = result;

        channel.set_session_id(*session.id());
        self.session_contexts.lock().unwrap().insert(
            *channel_id,
            self.session_context(*channel_id, session, true),
        );
        self.put_channel(channel)?;
        Ok(())
    }

    pub(crate) async fn update_channel_info(&self, channel: &Channel) -> Result<()> {
        let Some(mut current) = self.channel(channel.id()) else {
            return Err(StateError::new("Channel not found").into());
        };
        if channel.owner() != self.user_id() {
            return Err(StateError::new("Only the channel owner can update channel information"));
        }

        let mut changes = ChannelInfoUpdate::new();
        if current.permission() != channel.permission() {
            changes = changes.permission(channel.permission());
        }
        if current.name() != channel.name() {
            changes = changes.name(channel.name().map(ToString::to_string));
        }
        if current.notice().as_deref() != channel.notice() {
            changes = changes.notice(channel.notice().map(ToString::to_string));
        }
        if current.is_announced() != channel.is_announced() {
            changes = changes.announced(channel.is_announced());
        }
        if changes.is_empty() {
            return Err(ArgumentError::new("Channel information has not changed").into());
        }

        // Build the request, send it and check the reply carries no result.
        let request = RPCRequest::update_channel_info(0, changes);

        let result = self.send_rpccall(channel.id(), request).await?;
        let _ = result;

        // Apply the confirmed change to the local channel.
        current.set_permission(channel.permission());
        current.set_name(channel.name().map(ToString::to_string));
        current.set_notice(channel.notice().map(ToString::to_string));
        current.set_announced(channel.is_announced());
        current.set_updated_at(boson_api::as_ms!(SystemTime::now()) as i64);
        // let contact = Self::to_photon_contact_ops(current.contact_box().as_ref())?;
        self.put_channel(current)?;
        //self.channel_listener.on_channel_updated(&current);
        Ok(())
    }

    pub(crate) async fn set_channel_members_role(
        &self,
        channel_id: &Id,
        members: &[Id],
        role: Role,
    ) -> Result<()> {
        let Some(mut channel) = self.get_channel(channel_id) else {
            return Err(StateError::new("Channel not found").into());
        };
        if !channel
            .member(self.user_id())
            .is_some_and(|v| v.is_owner() || v.is_moderator())
        {
            return Err(StateError::new(
                "Only a channel owner or moderator can manage members",
            ).into());
        }

        let request = RPCRequest::update_channel_members_role(0, members.to_vec(), role);
        let response = self.send_rpccall(channel_id, request).await?;
        let ids = match response {
            ResponseParams::ChannelMembersRoleUpdate(ids) => ids,
            _ => return Err(StateError::new("Unexpected response").into()),
        };

        let _ = channel.update_member_roles(&ids, role);
        self.put_channel(channel)?;
        Ok(())
    }

    pub(crate) async fn ban_channel_members(&self, channel_id: &Id, members: &[Id]) -> Result<()> {
        let Some(mut channel) = self.channel(channel_id) else {
            return Err(StateError::new("Channel not found").into());
        };
        if !channel
            .member(self.user_id())
            .is_some_and(|member| member.is_owner() || member.is_moderator())
        {
            return Err(StateError::new(
                "Only a channel owner or moderator can manage members",
            ).into());
        }

        let request = RPCRequest::ban_channel_members(0, members.to_vec());
        let result = self.send_rpccall(channel_id, request).await?;
        let ids = match result {
            ResponseParams::ChannelMembersBan(ids) => ids,
            _ => return Err(StateError::new("Unexpected response").into()),
        };

        let _ = channel.update_member_roles(&ids, Role::Banned);
        self.put_channel(channel)?;
        Ok(())
    }

    pub(crate) async fn unban_channel_members(
        &self,
        channel_id: &Id,
        members: &[Id],
    ) -> Result<()> {
        let Some(mut channel) = self.channel(channel_id) else {
            return Err(StateError::new("Channel is not existed").into());
        };
        if !channel
            .member(self.user_id())
            .is_some_and(|member| member.is_owner() || member.is_moderator())
        {
            return Err(StateError::new(
                "Only a channel owner or moderator can manage members",
            ).into());
        }

        let request = RPCRequest::unban_channel_members(0, members.to_vec());
        let result = self.send_rpccall(channel_id, request).await?;

        let ids = match result {
            ResponseParams::ChannelMembersUnban(ids) => ids,
            _ => return Err(StateError::new("Unexpected response").into()),
        };

        let _ = channel.update_member_roles(&ids, Role::Member);
        self.put_channel(channel)?;

        Ok(())
    }

    pub(crate) async fn remove_channel_members(
        &self,
        channel_id: &Id,
        members: &[Id],
    ) -> Result<()> {
        let Some(mut channel) = self.channel(channel_id) else {
            return Err(StateError::new("Channel not found").into());
        };
        if !channel
            .member(self.user_id())
            .is_some_and(|member| member.is_owner() || member.is_moderator())
        {
            return Err(StateError::new(
                "Only a channel owner or moderator can manage members",
            ).into());
        }

        let request = RPCRequest::remove_channel_members(0, members.to_vec());

        let result = self.send_rpccall(channel_id, request).await?;
        let ids = match result {
            ResponseParams::ChannelMembersRemove(ids) => ids,
            _ => return Err(StateError::new("Unexpected response").into()),
        };

        let _ = channel.remove_members(&ids);
        self.put_channel(channel)?;
        Ok(())
    }

    pub(crate) async fn get_contacts(
        &self,
        id_opt: Option<&Id>
    ) -> Result<Vec<Contact>> {
        Ok(match id_opt {
            Some(id) => self.contact(id).await.into_iter().map(|contact| Box::new(contact) as Contact).collect(),
            None => self.contacts().await.into_iter().map(|contact| Box::new(contact) as Contact).collect(),
        })
    }

    pub(crate) async fn update_contact(&self, contact: &Contact) -> Result<()> {
        let origin = self.contact(contact.id()).await;

        let Some(origin) = origin else {
            return Err(StateError::new("Contact not found"));
        };
        if origin.remark() == contact.remark()
            && origin.tags() == contact.tags()
            && origin.is_muted() == contact.is_muted()
            && origin.is_blocked() == contact.is_blocked()
        {
            return Err(StateError::new("No changes detected"));
        }
        if contact.revision() < origin.revision() {
            return Err(StateError::new(
                "Updated contact version is older than the current version",
            ));
        }

        let revision = self.contacts_revision.get();
        let next_revision = revision
            .checked_add(1)
            .ok_or_else(|| StateError::new("Contact revision is exhausted"))?;
        let mut data = ContactData::from(&origin);
        data.remark = contact.remark().map(ToString::to_string);
        data.tags = contact.tags().map(ToString::to_string);
        data.muted = contact.is_muted();
        data.blocked = contact.is_blocked();

        let now_timestamp = boson_api::as_ms!(SystemTime::now()) as i64;
        data.updated_at = now_timestamp.max(origin.updated_at());
        data.revision = next_revision;

        let session = self
            .session_contexts
            .lock()
            .unwrap()
            .get(contact.id())
            .cloned();
        let key = session
            .as_ref()
            .map(|session| {
                self.user_identity
                    .encrypt_into(self.user_id(), session.private_key())
            })
            .transpose()?;
        if let Some(key) = &key {
            data.set_session_key(key.clone());
        }
        let mut updated = data.contact(next_revision)?;
        let opaque = if origin.contact_type() == ContactType::Channel {
            let Some(channel) = self.channel(contact.id()).map(|v| Box::new(v) as Channel) else {
                return Err(StateError::new("Channel not found").into());
            };
            let key = key.ok_or_else(|| StateError::new("Channel session key is missing"))?;
            let Value::Map(mut document) = to_cbor(&data, "channel contact")? else {
                return Err(EncodingError::new("Channel contact is not a map").into());
            };
            Self::insert_channel_fields(&mut document, &channel, key.clone());
            let document = to_cbor_bytes(&Value::Map(document), "channel contact")?;
            let document = self.user_identity.encrypt_into(self.user_id(), &document)?;
            OpaqueContact::new(*contact.id(), next_revision, Value::Bytes(document))
        } else {
            data.encode_into(&self.user_identity)?
        };
        // 2. Build the request.
        let mutation = ContactMutation::update(revision, opaque);
        let request = RPCRequest::contact_mutate(0, mutation);

        // 3. Send it to the home peer and 4. decode the revision it reports.
        let result = self.send_rpccall(self.peer_id(), request).await?;
        let confirmed = match result {
            ResponseParams::ContactMutate(confirmed) => confirmed,
            _ => return Err(EncodingError::new("RPC result is not a contact revision").into()),
        };
        if confirmed < next_revision || confirmed < self.contacts_revision.get() {
            return Err(StateError::new("Contact update revision is outdated"));
        }
        self.contacts_revision.set(confirmed);

        // 5. Apply the confirmed change to the local state.
        updated.set_revision(confirmed);
        if let Some(mut channel) = self.channel(updated.id()) {
            channel.set_name(updated.name().map(ToString::to_string));
            channel.set_updated_at(updated.updated_at());
            channel.set_contact_revision(updated.revision());
            self.put_channel(channel)?;
        }
        if updated.is_blocked() {
            self.blocked_contacts.lock().unwrap().insert(*updated.id());
        } else {
            self.blocked_contacts.lock().unwrap().remove(updated.id());
        }
        if let Some(channel) = self.channel(updated.id()) {
            self.put_channel(channel)?;
        } else {
            let session_key = self.persisted_session_key(updated.id()).ok();
            self.repository.borrow_mut().put_contact(
                self.contacts_revision.get(),
                &updated,
                session_key.as_deref(),
            )?;
        }
        // 6. Notify the application.
        let updated_contact: Contact = Box::new(updated.clone());
        self.contact_listener.on_contacts_updated(&[updated_contact]);
        Ok(())
    }

    pub(crate) async fn clear_contacts(&self) -> Result<()> {
        let revision = self.contacts_revision.get();

        let mutation = ContactMutation::clear(revision);
        let request = RPCRequest::contact_mutate(0, mutation);

        let result = self.send_rpccall(self.peer_id(), request).await?;
        let confirmed = match result {
            ResponseParams::ContactMutate(confirmed) => confirmed,
            _ => return Err(EncodingError::new("RPC result is not a contact revision").into()),
        };
        if confirmed < revision || confirmed < self.contacts_revision.get() {
            return Err(StateError::new("Contact clear revision is outdated"));
        }

        self.contacts_revision.set(confirmed);
        self.session_contexts.lock().unwrap().clear();
        self.blocked_contacts.lock().unwrap().clear();
        self.repository.borrow_mut().clear_contacts(confirmed)?;
        self.contact_listener.on_contacts_cleared();

        Ok(())
    }

    pub(crate) fn message(&self, recipient: Option<Id>) -> Box<dyn MessageBuilderOps> {
        Box::new(SessionMessageBuilder {
            recipient,
            client: self.client_handle(),
            user_identity: self.user_identity.clone(),
            device_identity: self.device_identity.clone(),
            friend_sessions: self.session_contexts.clone(),
            blocked_contacts: self.blocked_contacts.clone(),
            origin_timestamp: self.origin_timestamp() as i64,
            conversation_contact: recipient.and_then(|id| {
                self.repository
                    .borrow_mut()
                    .contact(&id)
                    .ok()
                    .flatten()
                    .map(|contact| Box::new(contact) as Contact)
            }),
            conversations: self.repository.borrow().conversations_handle(),
            peer_id: *self.peer_id(),
            content_type: None,
            content_disposition: None,
            headers: Vec::new(),
            body: None,
            text: false,
        })
    }

    /// Splices the channel-only fields into an encoded contact document.
    ///
    /// `store_channel` and `update_contact` must produce byte-identical layouts, so
    /// both build their document through this function.
    fn insert_channel_fields(
        document: &mut BTreeMap<Value, Value>,
        channel: &Channel,
        session_key: Vec<u8>,
    ) {
        document.insert(
            Value::Text(FIELD_SESSION_KEY.into()),
            Value::Bytes(session_key),
        );
        document.insert(
            Value::Text(FIELD_OWNER.into()),
            Value::Bytes(channel.owner().as_bytes().to_vec()),
        );
        document.insert(
            Value::Text(FIELD_PERMISSION.into()),
            Value::Integer((channel.permission() as i32).into()),
        );
        document.insert(
            Value::Text(FIELD_NOTICE.into()),
            channel
                .notice()
                .map(|notice| Value::Text(notice.to_string()))
                .unwrap_or(Value::Null),
        );
        document.insert(
            Value::Text(FIELD_ANNOUNCED.into()),
            Value::Bool(channel.is_announced()),
        );
    }

}

/// Collects a message on this side, then publishes it.
///
/// The session itself stays on the verticle thread, so the builder captures the
/// pieces it needs (identities, the MQTT handle, the conversation cache) and
/// does all encoding and encryption on the caller's thread.
pub(crate) struct SessionMessageBuilder {
    recipient: Option<Id>,
    client: ClientHandle,
    user_identity: CryptoIdentity,
    device_identity: CryptoIdentity,
    friend_sessions: Arc<std::sync::Mutex<HashMap<Id, SessionContext>>>,
    blocked_contacts: Arc<std::sync::Mutex<HashSet<Id>>>,
    origin_timestamp: i64,
    conversation_contact: Option<Contact>,
    conversations: Arc<Mutex<HashMap<Id, PhotonConversation>>>,
    peer_id: Id,
    content_type: Option<String>,
    content_disposition: Option<ContentDisposition>,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    text: bool,
}

impl MessageBuilderOps for SessionMessageBuilder {
    fn with_content_type(mut self: Box<Self>, content_type: &str) -> Box<dyn MessageBuilderOps> {
        self.content_type = Some(content_type.to_string());
        self
    }

    fn with_content_disposition(mut self: Box<Self>, disposition: ContentDisposition) -> Box<dyn MessageBuilderOps> {
        self.content_disposition = Some(disposition);
        self
    }

    fn with_text_body(mut self: Box<Self>, text: &str) -> Box<dyn MessageBuilderOps> {
        self.body = Some(text.as_bytes().to_vec());
        self.text = true;
        self
    }

    fn with_binary_body(mut self: Box<Self>, data: Vec<u8>) -> Box<dyn MessageBuilderOps> {
        self.body = Some(data);
        self.text = false;
        self
    }

    fn with_header(mut self: Box<Self>, key: &str, value: &str) -> Box<dyn MessageBuilderOps> {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    fn send(self: Box<Self>) -> Pin<Box<dyn Future<Output = Result<Message>> + Send>> {
        Box::pin(async move {
            let this = *self;
            let recipient = this
                .recipient
                .ok_or_else(|| ArgumentError::new("Message recipient is required"))?;
            if this.blocked_contacts.lock().unwrap().contains(&recipient) {
                return Err(StateError::new("Cannot send a message to a blocked contact").into());
            }
            let mqtt: mqtt::Client = this
                .client
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| StateError::new("Messaging client is not running"))?;
            let body = this
                .body
                .ok_or_else(|| ArgumentError::new("Message content is required"))?;
            let headers = build_message_headers(
                this.headers,
                this.content_type,
                this.content_disposition,
                this.text,
            );

            let timestamp = this.origin_timestamp;
            let content = PhotonContent {
                headers: headers_to_cbor(&headers)?,
                format: if this.text {
                    ContentFormat::Text
                } else {
                    ContentFormat::Binary
                },
                body: if this.text {
                    Value::Text(
                        String::from_utf8(body.clone())
                            .map_err(|_| EncodingError::new("Text message is not UTF-8"))?,
                    )
                } else {
                    Value::Bytes(body.clone())
                },
            };
            let content_bytes = to_cbor_bytes(&content, "message content")?;
            let encrypted = {
                let mut sessions = this.friend_sessions.lock().unwrap();
                let session = sessions
                    .get_mut(&recipient)
                    .ok_or_else(|| StateError::new(format!("No friend session for {recipient}")))?;
                session.tx_crypto_context()?.encrypt_into(&content_bytes)?
            };
            let (mut wire, payload) = super::transport::seal_for(
                &this.user_identity,
                &this.device_identity,
                &this.peer_id,
                &recipient,
                MessageType::Content as u8,
                timestamp,
                encrypted,
                None,
                "content",
            )?;
            super::transport::publish_outbox(&mqtt, payload, "message").await?;

            // The returned message mirrors what a recipient would see, so the
            // caller can render it without a round trip.
            wire.set_from(*this.user_identity.id());
            wire.set_sent(boson_api::as_ms!(SystemTime::now()) as i64);
            wire.payload_bytes = content_bytes;
            wire.content = Some(content);
            wire.set_converstation_id(recipient);
            let contact = this
                .conversation_contact
                .unwrap_or_else(|| Box::new(PhotonContact::new(recipient, ContactType::Auto, timestamp)) as Contact);
            let boxed_message: Message = Box::new(wire);
            update_conversation(&this.conversations, contact, boxed_message.clone())?;
            Ok(boxed_message)
        })
    }
}

/// Folds the typed builder fields into the header map the wire format takes.
///
/// A non-text body defaults to `application/octet-stream`; an explicit content
/// type always wins, and so does an explicit content disposition.
fn build_message_headers(
    headers: Vec<(String, String)>,
    declared_type: Option<String>,
    disposition: Option<ContentDisposition>,
    text: bool,
) -> HashMap<String, serde_json::Value> {
    let mut merged: HashMap<String, serde_json::Value> = headers
        .into_iter()
        .map(|(key, value)| (key, serde_json::Value::String(value)))
        .collect();

    if let Some(declared_type) = declared_type {
        merged.insert(
            content_type::HEADER_NAME.into(),
            serde_json::Value::String(declared_type),
        );
    } else if !text && !merged.contains_key(content_type::HEADER_NAME) {
        merged.insert(
            content_type::HEADER_NAME.into(),
            serde_json::Value::String(content_type::ContentType::ApplicationOctetStream.as_str().into()),
        );
    }

    if let Some(disposition) = disposition {
        merged.insert(
            ContentDisposition::HEADER_NAME.into(),
            serde_json::Value::String(disposition.value()),
        );
    }
    merged
}

/// Converts JSON header values into their CBOR representation.
fn headers_to_cbor(headers: &HashMap<String, serde_json::Value>) -> Result<HashMap<String, Value>> {
    headers
        .iter()
        .map(|(key, value)| {
            serde_cbor::value::to_value(value)
                .map(|value| (key.clone(), value))
                .map_err(|error| {
                    EncodingError::new(format!("Encoding header failed: {error}")).into()
                })
        })
        .collect()
}

/// Folds a message into its conversation, creating the conversation on demand.
pub(super) fn update_conversation(
    conversations: &Arc<Mutex<HashMap<Id, PhotonConversation>>>,
    contact: Contact,
    message: Message,
) -> Result<()> {
    let mut conversations = conversations.lock().unwrap();
    let conversation = conversations
        .entry(*contact.id())
        .or_insert_with(|| PhotonConversation::new(contact));
    conversation.update(message)
}

impl RpcServer {
    async fn send_message_internal(&self, mut message: PhotonMessage) -> Result<()> {
        use crate::MessageOps;

        let payload = message.payload_as_bytes();
        let encrypted = if payload.is_empty() {
            Vec::new()
        } else {
            match message.message_type() {
                MessageType::Content => {
                    let conversation_id = message
                        .conversation_id()
                        .copied()
                        .unwrap_or_else(|| *message.recipient());
                    let mut sessions = self.session_contexts.lock().unwrap();
                    let session = sessions.get_mut(&conversation_id).ok_or_else(|| {
                        StateError::new(format!(
                            "No channel session context for {conversation_id}"
                        ))
                    })?;
                    session.tx_crypto_context()?.encrypt_into(payload)?
                }
                MessageType::Control => {
                    if message.recipient() == self.peer_id() {
                        payload.to_vec()
                    } else {
                        self.user_identity
                            .encrypt_into(message.recipient(), payload)
                            .map_err(|error| {
                                EncodingError::new(format!(
                                    "Encrypting message payload failed: {error}"
                                ))
                            })?
                    }
                }
                MessageType::State => {
                    return Err(StateError::new(
                        "INTERNAL ERROR: messaging client is not supposed to send state messages",
                    )
                    .into());
                }
                MessageType::Handshake => self
                    .user_identity
                    .encrypt_into(message.recipient(), payload)
                    .map_err(|error| {
                        EncodingError::new(format!(
                            "Encrypting message payload failed: {error}"
                        ))
                    })?,
            }
        };

        message.set_payload(encrypted);
        let encoded = message.serialize()?;
        let envelope = self
            .device_identity
            .encrypt_into(self.peer_id(), &encoded)
            .map_err(|error| {
                AuthenticationError::new(format!("Encrypting message failed: {error}"))
            })?;

        let mqtt: mqtt::Client = self
            .mqtt_client
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| StateError::new("Messaging client is not running"))?;
        super::transport::publish_outbox(&mqtt, envelope, "message").await
    }

    pub(super)async fn send_rpccall(
        &self,
        recipient: &Id,
        request: RPCRequest,
    ) -> Result<ResponseParams> {
        let timestamp = self.origin_timestamp();
        let method = request.method();
        let request = request.with_id(timestamp);
        let payload = request.serialize()?;
        let call = self
            .pending_calls
            .register(timestamp, method, *recipient)?;

        let message_id = crate::interfaces::generate_id(self.device_identity.id(), timestamp);
        let mut message = PhotonMessage::new(
            MESSAGE_VERSION as i32,
            message_id,
            *recipient,
            MessageType::Control as i32,
            None,
            timestamp,
            Value::Bytes(payload.clone()),
        );
        message.payload_bytes = payload;

        tokio::time::timeout(RPC_TIMEOUT, async {
            self.send_message_internal(message).await?;
            call.await
        })
        .await
        .map_err(|_| {
            warn!("RPC '{method:?}' timed out");
            RPCError::timeout()
        })?
    }
}
