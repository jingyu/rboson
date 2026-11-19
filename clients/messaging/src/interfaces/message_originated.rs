use sha2::{Digest, Sha256};
use boson_api::Id;

pub trait MessageOriginated {
    fn id(&self) -> &Id;

    fn timestamp(&self) -> i64;

    fn is_originated(&self, device_id:&Id) -> bool {
        let timestamp = self.timestamp();
        match Self::try_generate_id(device_id, timestamp) {
            Some(id) => id == *self.id(),
            None => false,
        }
    }

    fn try_generate_id(device_id: &Id, timestamp: i64) -> Option<Id> {
        let mut sha = Sha256::new();
        sha.update(device_id.as_bytes());
        sha.update(&timestamp.to_le_bytes());
        let bytes = sha.finalize().to_vec();

        Id::try_from_bytes(&bytes).ok()
    }

    fn generate_id(device_id: &Id, timestamp: i64) -> Id {
        Self::try_generate_id(device_id, timestamp)
            .expect("Failed to generate ID")
    }
}

pub(crate) fn generate_id(device_id: &Id, timestamp: i64) -> Id {
    let mut sha = Sha256::new();
    sha.update(device_id.as_bytes());
    sha.update(&timestamp.to_le_bytes());
    let bytes = sha.finalize().to_vec();

    Id::try_from_bytes(&bytes).unwrap()
}
