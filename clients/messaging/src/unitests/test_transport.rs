use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use boson_api::{
    signature::KeyPair,
    CryptoIdentity,
    Identity,
};

use std::rc::Rc;

use crate::{
    internal::{photon_friend_request::PhotonFriendRequest, verticle::VerticleOptions},
    options::OptionsBuilder,
};

use super::*;

static NEXT_DB: AtomicUsize = AtomicUsize::new(0);

fn options() -> VerticleOptions {
    let mut builder = OptionsBuilder::new();
    builder.with_peer_id(*CryptoIdentity::new().id());
    builder.with_peer_endpoint("mqtt://127.0.0.1:1883").unwrap();
    builder.with_user_keypair(KeyPair::random());
    builder.with_device_keypair(KeyPair::random());
    let unique = format!(
        "boson-friend-request-test-{}-{}",
        std::process::id(),
        NEXT_DB.fetch_add(1, Ordering::Relaxed),
    );
    builder.with_data_dir(std::env::temp_dir().join(unique));
    let options = Arc::new(builder.build().unwrap());
    VerticleOptions {
        connection_listener: options.connection_listener(),
        message_listener: options.message_listener(),
        channel_listener: options.channel_listener(),
        contact_listener: options.contact_listener(),
        session_listener: options.session_listener(),
        friend_request_listener: options.friend_request_listener(),
        options,
    }
}

fn server() -> Rc<RpcServer> {
    let options = options();
    let path = options.options.database_path().to_path_buf();
    let _ = std::fs::remove_file(&path);
    let server = RpcServer::new(options).unwrap();
    server.repository.borrow_mut().open(&path).unwrap();
    server
}

fn request(user_id: Id, initiator_id: Id) -> PhotonFriendRequest {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    PhotonFriendRequest::new(user_id, initiator_id, Some("hello".into()), now)
}

#[tokio::test]
async fn friend_request_put_get_and_remove() {
    let server = server();
    let user_id = *CryptoIdentity::new().id();
    let initiator_id = *CryptoIdentity::new().id();
    let request = request(user_id, initiator_id);

    server.put_friend_request(&request).await.unwrap();

    let loaded = server.friend_request(&user_id).await.unwrap();
    assert_eq!(*loaded.user_id(), user_id);
    assert_eq!(*loaded.initiator_id(), initiator_id);
    assert_eq!(loaded.hello(), Some("hello"));

    server.remove_friend_request(&user_id).await.unwrap();
    assert!(server.friend_request(&user_id).await.is_none());
    assert!(server.friend_requests().await.is_empty());
}

#[tokio::test]
async fn friend_requests_reads_repository_and_cache() {
    let server = server();
    let first = request(*CryptoIdentity::new().id(), *CryptoIdentity::new().id());
    let second = request(*CryptoIdentity::new().id(), *CryptoIdentity::new().id());

    server.put_friend_request(&first).await.unwrap();
    server.put_friend_request(&second).await.unwrap();

    assert_eq!(server.friend_requests().await.len(), 2);

    server.friend_requests_cache.clear();
    let loaded = server.friend_requests().await;
    assert_eq!(loaded.len(), 2);
    assert!(loaded.iter().any(|request| request.user_id() == first.user_id()));
    assert!(loaded.iter().any(|request| request.user_id() == second.user_id()));
}

#[tokio::test]
async fn remove_friend_requests_removes_all_and_reports_errors() {
    let server = server();
    let first = request(*CryptoIdentity::new().id(), *CryptoIdentity::new().id());
    let second = request(*CryptoIdentity::new().id(), *CryptoIdentity::new().id());
    server.put_friend_request(&first).await.unwrap();
    server.put_friend_request(&second).await.unwrap();

    server
        .remove_friend_requests(&[*first.user_id(), *second.user_id()])
        .await
        .unwrap();

    assert!(server.friend_requests().await.is_empty());
    assert!(server.friend_request(first.user_id()).await.is_none());
    assert!(server.friend_request(second.user_id()).await.is_none());
}

#[tokio::test]
async fn clear_friend_request_clears_repository_and_cache() {
    let server = server();
    let request = request(*CryptoIdentity::new().id(), *CryptoIdentity::new().id());
    server.put_friend_request(&request).await.unwrap();

    server.clear_friend_request().await.unwrap();

    assert!(server.friend_requests().await.is_empty());
    assert!(server.friend_request(request.user_id()).await.is_none());
}
