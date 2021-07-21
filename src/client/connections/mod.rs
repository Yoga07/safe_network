// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod listeners;
mod messaging;

use crate::client::Error;
use crate::messaging::data::{CostInquiry, GuaranteedQuote, PaymentReceipt};
use crate::messaging::node::{KeyedSig, SigShare};
use crate::messaging::signature_aggregator::{Error as AggregatorError, SignatureAggregator};
use crate::messaging::{
    data::{CmdError, QueryResponse},
    MessageId,
};
use crate::types::PublicKey;
use bls::PublicKeySet;
use bytes::Bytes;
use itertools::Itertools;
use qp2p::{Config as QuicP2pConfig, Endpoint, QuicP2p};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tracing::{debug, trace};
use xor_name::{Prefix, XorName};

type QueryResponseSender = Sender<QueryResponse>;

type PendingQueryResponses = Arc<RwLock<HashMap<MessageId, QueryResponseSender>>>;

pub(crate) struct QueryResult {
    pub(super) response: QueryResponse,
    pub(super) msg_id: MessageId,
}

#[derive(Clone, Debug)]
pub(super) struct Session {
    pub(super) section_key_set: Arc<RwLock<Option<PublicKeySet>>>,
    qp2p: QuicP2p,
    pending_queries: PendingQueryResponses,
    incoming_err_sender: Arc<Sender<CmdError>>,
    endpoint: Option<Endpoint>,
    /// Elders of our section
    our_section: Arc<RwLock<BTreeMap<XorName, SocketAddr>>>,
    /// all elders we know about from SectionInfo messages
    all_known_sections: Arc<RwLock<BTreeMap<XorName, SocketAddr>>>,
    section_prefix: Arc<RwLock<Option<Prefix>>>,
    is_connecting_to_new_elders: bool,
    aggregator: SignatureAggregator,
}

impl Session {
    pub(super) fn new(
        qp2p_config: QuicP2pConfig,
        err_sender: Sender<CmdError>,
    ) -> Result<Self, Error> {
        debug!("QP2p config: {:?}", qp2p_config);

        let qp2p = qp2p::QuicP2p::with_config(Some(qp2p_config), Default::default(), true)?;
        Ok(Self {
            qp2p,
            pending_queries: Arc::new(RwLock::new(HashMap::default())),
            incoming_err_sender: Arc::new(err_sender),
            endpoint: None,
            section_key_set: Arc::new(RwLock::new(None)),
            our_section: Arc::new(RwLock::new(Default::default())),
            all_known_sections: Arc::new(RwLock::new(Default::default())),
            section_prefix: Arc::new(RwLock::new(None)),
            is_connecting_to_new_elders: false,
            aggregator: SignatureAggregator::new(),
        })
    }

    /// Get the elders count of our section elders as provided by SectionInfo
    pub(super) async fn known_elders_count(&self) -> usize {
        self.all_known_sections.read().await.len()
    }

    pub(super) fn endpoint(&self) -> Result<&Endpoint, Error> {
        match self.endpoint.borrow() {
            Some(endpoint) => Ok(endpoint),
            None => {
                trace!("self.endpoint.borrow() was None");
                Err(Error::NotBootstrapped)
            }
        }
    }

    pub(super) async fn section_key(&self) -> Result<PublicKey, Error> {
        let keys = self.section_key_set.read().await.clone();

        match keys.borrow() {
            Some(section_key_set) => Ok(PublicKey::Bls(section_key_set.public_key())),
            None => {
                trace!("self.section_key_set.borrow() was None");
                Err(Error::NotBootstrapped)
            }
        }
    }

    pub(super) async fn fetch_quote(&self, inquiry: CostInquiry) -> Result<GuaranteedQuote, Error> {
        let payment_xorname = inquiry.payment_xorname()?;
        let elders = self
            .all_known_sections
            .read()
            .await
            .clone()
            .into_iter()
            .sorted_by(|(lhs_name, _), (rhs_name, _)| {
                payment_xorname.cmp_distance(lhs_name, rhs_name)
            })
            .map(|(_, addrs)| addrs.values())
            .collect::<Vec<SocketAddr>>();

        self.send_inquiry(inquiry, elders)
    }

    pub fn aggregate_incoming_message(
        &mut self,
        bytes: Bytes,
        sig_share: SigShare,
    ) -> Result<Option<Bytes>, Error> {
        match self.aggregator.add(&bytes, sig_share) {
            Ok(key_sig) => {
                if key_sig.public_key.verify(&key_sig.signature, &bytes) {
                    Ok(Some(bytes))
                } else {
                    Err(Error::Aggregation(
                        "Failed to verify aggregated signature".to_string(),
                    ))
                }
            }
            Err(AggregatorError::NotEnoughShares) => Ok(None),
            Err(e) => Err(Error::Aggregation(e.to_string())),
        }
    }
}
