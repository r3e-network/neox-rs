//! Cache for authenticated dBFT messages that arrive before this node can act on them.

use alloy_primitives::B512;
use reth_neox_chainspec::NEOX_MAX_VALIDATOR_COUNT;
use reth_neox_network::{DbftMessage, DbftMessageType};
use std::{collections::BTreeMap, sync::Arc};

/// Caches authenticated dBFT messages the active round cannot accept yet, and replays them once it
/// can.
///
/// The reference client's dBFT state machine caches a message whose height is above the round's,
/// and one whose view is above the round's unless it is a change-view or a recovery message. It
/// replays the bucket for its own height whenever it initializes a round or changes view, in the
/// order preparation, change view, pre-commit, commit, feeding each message back through the normal
/// receive path. Dropping those messages instead costs a validator that is briefly behind the whole
/// quorum for the next height: it starts that round with nothing, waits out a view timeout, and
/// recovers state its peers had already sent it.
///
/// Unlike the reference client this cache is bounded. The reference implementation retains every
/// future height it is told about and never prunes a height it skipped, so the cache can grow
/// without limit. The bounds here evict in the order that costs least: heights nearest the round
/// are the ones this node is about to reach, so pressure evicts from the top.
#[derive(Debug, Default)]
pub(super) struct FutureDbftMessages {
    heights: BTreeMap<u64, HeightBucket>,
    bytes: usize,
}

impl FutureDbftMessages {
    /// Caches one authenticated message, returning whether it was retained.
    ///
    /// A later message from the same validator, height, and bucket replaces the earlier one,
    /// matching the reference client, whose cache is keyed by validator index within each
    /// bucket.
    pub(super) fn insert(
        &mut self,
        peer_id: B512,
        message: Arc<DbftMessage>,
        kind: CachedMessageKind,
    ) -> bool {
        let height = message.valid_block_end;
        let Some(index) = cached_validator_index(&message) else { return false };
        let size = cached_size(&message);
        if size > MAX_CACHED_BYTES {
            return false
        }
        if !self.make_room(height, size) {
            return false
        }
        let bucket = self.heights.entry(height).or_default();
        let slot = &mut bucket.slots[kind as usize][index];
        if let Some((_, previous)) = slot.replace((peer_id, message)) {
            self.bytes -= cached_size(&previous);
        }
        self.bytes += size;
        true
    }

    /// Removes and returns the messages cached for one height, in the reference client's replay
    /// order.
    pub(super) fn take_height(&mut self, height: u64) -> Vec<CachedDbftMessage> {
        let Some(bucket) = self.heights.remove(&height) else { return Vec::new() };
        let mut messages = Vec::with_capacity(bucket.len());
        for slots in bucket.slots {
            for entry in slots.into_iter().flatten() {
                self.bytes -= cached_size(&entry.1);
                messages.push(entry);
            }
        }
        messages
    }

    /// Drops every height at or below `height`, which no round will ask for again.
    ///
    /// The reference client leaks these: it only removes the bucket for the height it is replaying,
    /// so a height it skipped stays cached for the rest of the process's life.
    pub(super) fn prune_through(&mut self, height: u64) {
        while let Some((&lowest, _)) = self.heights.first_key_value() {
            if lowest > height {
                break
            }
            self.remove_height(lowest);
        }
    }

    /// Number of cached messages.
    pub(super) fn len(&self) -> usize {
        self.heights.values().map(HeightBucket::len).sum()
    }

    /// Frees space for one message of `size` bytes at `height`, returning whether it now fits.
    ///
    /// Eviction takes the highest cached height first, so a flood of far-future messages cannot
    /// push out the height this node is about to reach. A message that is itself at or above
    /// the highest cached height is refused instead, rather than admitted by evicting something
    /// more useful.
    fn make_room(&mut self, height: u64, size: usize) -> bool {
        while self.heights.len() >= MAX_CACHED_HEIGHTS && !self.heights.contains_key(&height) {
            let Some((&highest, _)) = self.heights.last_key_value() else { break };
            if highest < height {
                return false
            }
            self.remove_height(highest);
        }
        while self.bytes + size > MAX_CACHED_BYTES {
            let Some((&highest, _)) = self.heights.last_key_value() else { break };
            if highest < height {
                return false
            }
            self.remove_height(highest);
            if highest == height {
                // The bucket this message belongs to is the one that was evicted, so there is no
                // longer anything for it to make room in.
                return false
            }
        }
        true
    }

    fn remove_height(&mut self, height: u64) {
        let Some(bucket) = self.heights.remove(&height) else { return };
        for slots in &bucket.slots {
            for entry in slots.iter().flatten() {
                self.bytes -= cached_size(&entry.1);
            }
        }
    }
}

/// One cached message and the peer that sent it.
///
/// The peer is retained because replaying a proposal starts a transaction request against whoever
/// sent it, so a replayed message has to ask its own source rather than an arbitrary peer.
pub(super) type CachedDbftMessage = (B512, Arc<DbftMessage>);

/// Replay bucket a cached message belongs to, which is also its replay order.
///
/// The variants are ordered to match the reference client's replay order, and their discriminants
/// index the per-height slots directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CachedMessageKind {
    /// Prepare requests and responses, replayed first.
    Preparation = 0,
    /// Change-view messages.
    ChangeView = 1,
    /// Anti-MEV pre-commit shares.
    PreCommit = 2,
    /// Commit shares, replayed last.
    Commit = 3,
}

impl CachedMessageKind {
    /// Returns the bucket for a message type, or `None` for the types the reference client
    /// discards.
    pub(super) const fn from_message_type(message_type: DbftMessageType) -> Option<Self> {
        match message_type {
            DbftMessageType::PrepareRequest | DbftMessageType::PrepareResponse => {
                Some(Self::Preparation)
            }
            DbftMessageType::ChangeView => Some(Self::ChangeView),
            DbftMessageType::PreCommit => Some(Self::PreCommit),
            DbftMessageType::Commit => Some(Self::Commit),
            DbftMessageType::RecoveryRequest | DbftMessageType::RecoveryMessage => None,
        }
    }
}

/// Number of replay buckets per height, one per [`CachedMessageKind`].
const CACHED_MESSAGE_KINDS: usize = 4;

/// Highest number of distinct future heights retained at once.
///
/// A validator further behind than this cannot use the cache anyway: it will not reach those
/// heights while the messages for them still matter, and it recovers state from its peers when it
/// does.
const MAX_CACHED_HEIGHTS: usize = 8;

/// Total encoded size retained across all heights.
///
/// A prepare request carries one hash per proposed transaction, so a single height can be large.
/// The payoff for caching is only ever saving a view timeout, so the budget stays well below what
/// holding full blocks would cost.
const MAX_CACHED_BYTES: usize = 16 * 1024 * 1024;

/// One height's messages, bucketed by replay order and then by validator index.
#[derive(Debug)]
struct HeightBucket {
    slots: [[Option<CachedDbftMessage>; NEOX_MAX_VALIDATOR_COUNT]; CACHED_MESSAGE_KINDS],
}

impl Default for HeightBucket {
    fn default() -> Self {
        Self { slots: core::array::from_fn(|_| core::array::from_fn(|_| None)) }
    }
}

impl HeightBucket {
    fn len(&self) -> usize {
        self.slots.iter().flatten().filter(|slot| slot.is_some()).count()
    }
}

/// Encoded size a cached message occupies, used for the cache's byte budget.
fn cached_size(message: &DbftMessage) -> usize {
    message.data.len() + message.witness.len()
}

/// Slot index for an authenticated message's sender, or `None` if it has no slot.
///
/// Validator indexes are one byte on the wire. Cache capacity therefore covers the full protocol
/// range, while the active round still rejects an index outside its configured committee.
fn cached_validator_index(message: &DbftMessage) -> Option<usize> {
    let index = usize::from(message.consensus_data().ok()?.validator_index);
    (index < NEOX_MAX_VALIDATOR_COUNT).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes};
    use alloy_rlp::Encodable;
    use reth_neox_network::DbftConsensusData;

    #[test]
    fn replays_a_height_in_the_reference_client_order() {
        // The reference client drains a cached height as preparation, change view, pre-commit,
        // commit, whatever the arrival order was.
        let mut cache = FutureDbftMessages::default();
        for message_type in [
            DbftMessageType::Commit,
            DbftMessageType::PreCommit,
            DbftMessageType::ChangeView,
            DbftMessageType::PrepareRequest,
        ] {
            assert!(cache.insert(peer(1), message(9, 0, message_type), kind_of(message_type)));
        }

        let replayed = cache.take_height(9);

        let types = replayed
            .iter()
            .map(|(_, message)| message.consensus_data().unwrap().message_type)
            .collect::<Vec<_>>();
        assert_eq!(
            types,
            vec![
                DbftMessageType::PrepareRequest,
                DbftMessageType::ChangeView,
                DbftMessageType::PreCommit,
                DbftMessageType::Commit,
            ]
        );
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn keeps_one_message_per_validator_and_bucket() {
        // The reference client's cache is keyed by validator index inside each bucket, so a
        // validator that sends twice for one height replaces its own entry instead of
        // adding another.
        let mut cache = FutureDbftMessages::default();
        let response = kind_of(DbftMessageType::PrepareResponse);
        assert!(cache.insert(peer(1), message(9, 3, DbftMessageType::PrepareResponse), response));
        assert!(cache.insert(peer(2), message(9, 3, DbftMessageType::PrepareRequest), response));
        assert!(cache.insert(peer(3), message(9, 4, DbftMessageType::PrepareResponse), response));

        assert_eq!(cache.len(), 2);
        let replayed = cache.take_height(9);
        assert_eq!(replayed.len(), 2);
        // The replacement kept the later message, and with it the peer to ask for its transactions.
        assert_eq!(replayed[0].0, peer(2));
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn caches_the_full_wire_validator_index_range() {
        let mut cache = FutureDbftMessages::default();
        let index = u8::MAX;

        assert!(cache.insert(
            peer(1),
            message(9, index, DbftMessageType::Commit),
            CachedMessageKind::Commit
        ));

        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn evicts_the_highest_height_under_pressure() {
        // Heights nearest the round are the ones this node is about to reach, so a flood of
        // far-future messages must not displace them.
        let mut cache = FutureDbftMessages::default();
        let first = 100;
        let cap = u64::try_from(MAX_CACHED_HEIGHTS).unwrap();
        for offset in 0..cap {
            assert!(cache.insert(
                peer(1),
                message(first + offset, 0, DbftMessageType::Commit),
                CachedMessageKind::Commit
            ));
        }

        // A height above everything cached is refused rather than admitted by eviction.
        assert!(!cache.insert(
            peer(1),
            message(first + 500, 0, DbftMessageType::Commit),
            CachedMessageKind::Commit
        ));
        assert!(cache.heights.contains_key(&(first + cap - 1)));

        // A height below the top evicts the top to make room for itself.
        assert!(cache.insert(
            peer(1),
            message(first - 1, 0, DbftMessageType::Commit),
            CachedMessageKind::Commit
        ));
        assert_eq!(cache.heights.len(), MAX_CACHED_HEIGHTS);
        assert!(cache.heights.contains_key(&(first - 1)));
        assert!(!cache.heights.contains_key(&(first + cap - 1)));
    }

    #[test]
    fn forgets_heights_the_round_passed() {
        let mut cache = FutureDbftMessages::default();
        for height in 5..=8 {
            assert!(cache.insert(
                peer(1),
                message(height, 0, DbftMessageType::Commit),
                CachedMessageKind::Commit
            ));
        }

        cache.prune_through(6);

        assert_eq!(cache.heights.keys().copied().collect::<Vec<_>>(), vec![7, 8]);
        assert_eq!(cache.len(), 2);
        cache.prune_through(8);
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn does_not_cache_recovery_control_messages() {
        // The reference client's cache stores only the four types it replays; it is handed recovery
        // control messages and discards them.
        assert!(CachedMessageKind::from_message_type(DbftMessageType::RecoveryRequest).is_none());
        assert!(CachedMessageKind::from_message_type(DbftMessageType::RecoveryMessage).is_none());
    }

    fn kind_of(message_type: DbftMessageType) -> CachedMessageKind {
        CachedMessageKind::from_message_type(message_type).unwrap()
    }

    fn peer(byte: u8) -> B512 {
        B512::repeat_byte(byte)
    }

    fn message(
        height: u64,
        validator_index: u8,
        message_type: DbftMessageType,
    ) -> Arc<DbftMessage> {
        let data = DbftConsensusData {
            message_type,
            block_index: height,
            validator_index,
            view_number: 0,
            payload: alloy_rlp::encode(Bytes::new()).into(),
        };
        let mut encoded = Vec::new();
        data.encode(&mut encoded);
        Arc::new(DbftMessage {
            valid_block_start: 0,
            valid_block_end: height,
            sender: Address::repeat_byte(validator_index.wrapping_add(1)),
            data: encoded.into(),
            witness: Bytes::from_static(&[0x01; 65]),
        })
    }
}
