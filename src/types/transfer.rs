// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{
    keys::{PublicKey, Signature, SignatureShare},
    token::Token,
    utils, Error, Result, SectionElders,
};
use bls::PublicKeySet;
use crdts::Dot;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use tiny_keccak::{Hasher, Sha3};

/// Debit ID.
pub type DebitId = Dot<PublicKey>;
/// Credit ID is the hash of the DebitId.
pub type CreditId = [u8; 256 / 8];
/// Msg, containing any data to the recipient.
pub type Msg = String;

/// Contains info on who the replicas
/// of this wallet are, and the wallet history at them.
#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct WalletHistory {
    ///
    pub replicas: SectionElders,
    ///
    pub history: ActorHistory,
}

impl Debug for WalletHistory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WalletHistory {{ replicas: PkSet {{ public_key: {:?} }},  history: {:?} }}",
            self.replicas.key_set.public_key(),
            self.history
        )
    }
}

/// A cmd to transfer of tokens between two keys.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct Transfer {
    /// The amount to transfer.
    pub amount: Token,
    /// The destination to transfer to.
    pub to: PublicKey,
    /// Debit ID, containing source key.
    pub debit_id: DebitId,
    /// Msg, containing any data to the recipient.
    pub msg: Msg,
}

impl Transfer {
    /// The source.
    pub fn debit(&self) -> Debit {
        Debit {
            id: self.debit_id,
            amount: self.amount,
        }
    }

    /// The destination.
    pub fn credit(&self) -> Result<Credit> {
        Ok(Credit {
            id: self.debit().credit_id()?,
            amount: self.amount,
            recipient: self.to,
            msg: self.msg.to_string(),
        })
    }
}

/// A debit of tokens at a key.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct Debit {
    /// Debit ID, containing source key.
    pub id: DebitId,
    /// The amount to debit.
    pub amount: Token,
}

impl Debit {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.id
    }

    /// Get the amount of this debit
    pub fn amount(&self) -> Token {
        self.amount
    }

    /// Get the key to be debited
    pub fn sender(&self) -> PublicKey {
        self.id.actor
    }

    ///
    pub fn credit_id(&self) -> Result<CreditId> {
        let id_bytes = &utils::serialise(&self.id)?;
        let mut hasher = Sha3::v256();
        let mut output = [0; 32];
        hasher.update(&id_bytes);
        hasher.finalize(&mut output);
        Ok(output)
    }
}

/// A debit of tokens at a key.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct Credit {
    /// Unique id for the credit, being the hash of the DebitId.
    pub id: CreditId,
    /// The amount to credit.
    pub amount: Token,
    /// The recipient key
    pub recipient: PublicKey,
    /// Msg, containing any data to the recipient.
    pub msg: Msg,
}

impl Credit {
    /// Get the credit id
    pub fn id(&self) -> &CreditId {
        &self.id
    }

    /// Get the amount of this credit
    pub fn amount(&self) -> Token {
        self.amount
    }

    /// Get the key to be credited
    pub fn recipient(&self) -> PublicKey {
        self.recipient
    }
}

/// The history of a transfer Actor.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorHistory {
    /// All the credits.
    pub credits: Vec<CreditAgreementProof>,
    /// All the debits.
    pub debits: Vec<TransferAgreementProof>,
}

impl ActorHistory {
    /// Returns empty history.
    pub fn empty() -> Self {
        Self {
            credits: vec![],
            debits: vec![],
        }
    }

    /// Returns `true` if the history contains no elements.
    pub fn is_empty(&self) -> bool {
        self.credits.is_empty() && self.debits.is_empty()
    }

    /// Returns the number of elements in the history, also referred to
    /// as its 'length'.
    pub fn len(&self) -> usize {
        self.credits.len() + self.debits.len()
    }
}

/// The aggregated Replica signatures of the Actor debit cmd.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreditAgreementProof {
    /// The cmd generated by sender Actor.
    pub signed_credit: SignedCredit,
    /// Quorum of Replica sigs over the credit.
    pub debiting_replicas_sig: Signature,
    /// PublicKeySet of the replica when it validated the debit.
    pub debiting_replicas_keys: ReplicaPublicKeySet,
}

impl Debug for CreditAgreementProof {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "CreditAgreementProof::")?;
        write!(formatter, "Credit({})", self.signed_credit.amount())?;
        write!(formatter, "ActorSignature::")?;
        Debug::fmt(&self.signed_credit.actor_signature, formatter)?;
        write!(formatter, "ReplicaSignature::")?;
        Debug::fmt(&self.debiting_replicas_sig, formatter)
    }
}

impl Display for CreditAgreementProof {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}

impl CreditAgreementProof {
    /// Get the credit id
    pub fn id(&self) -> &CreditId {
        self.signed_credit.id()
    }

    /// Get the amount of this credit
    pub fn amount(&self) -> Token {
        self.signed_credit.amount()
    }

    /// Get the recipient of this credit
    pub fn recipient(&self) -> PublicKey {
        self.signed_credit.recipient()
    }

    /// Get the PublicKeySet of the replica that validated this credit
    pub fn replica_keys(&self) -> ReplicaPublicKeySet {
        self.debiting_replicas_keys.clone()
    }
}

/// The aggregated Replica signatures of the Actor debit cmd.
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferAgreementProof {
    /// The debit generated by sender Actor.
    pub signed_debit: SignedDebit,
    /// The credit generated by sender Actor.
    pub signed_credit: SignedCredit,
    /// Quorum of Replica sigs over the debit.
    pub debit_sig: Signature,
    /// Quorum of Replica sigs over the credit.
    pub credit_sig: Signature,
    /// PublicKeySet of the replica when it validated the transfer.
    pub debiting_replicas_keys: ReplicaPublicKeySet,
}

impl TransferAgreementProof {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.signed_debit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.signed_debit.amount()
    }

    /// Get the sender of this transfer
    pub fn sender(&self) -> PublicKey {
        self.signed_debit.sender()
    }

    /// Get the recipient of this transfer
    pub fn recipient(&self) -> PublicKey {
        self.signed_credit.recipient()
    }

    /// Get the PublicKeySet of the replica that validated this transfer
    pub fn replica_keys(&self) -> ReplicaPublicKeySet {
        self.debiting_replicas_keys.clone()
    }

    /// Get the corresponding credit agreement proof.
    pub fn credit_proof(&self) -> CreditAgreementProof {
        CreditAgreementProof {
            signed_credit: self.signed_credit.clone(),
            debiting_replicas_sig: self.credit_sig.clone(),
            debiting_replicas_keys: self.replica_keys(),
        }
    }
}

impl Debug for TransferAgreementProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransferAgreementProof {{ signed_debit: {:?}, signed_credit: {:?}, debit_sig: {:?}, credit_sig: {:?}, debiting_replicas_keys: PkSet {{ public_key: {:?} }} }}",
            self.signed_debit,
            self.signed_credit,
            self.debit_sig,
            self.credit_sig,
            self.debiting_replicas_keys.public_key()
        )
    }
}

/// An Actor cmd.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct SignedTransfer {
    /// The debit.
    pub debit: SignedDebit,
    /// The credit.
    pub credit: SignedCredit,
}

impl SignedTransfer {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.debit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.debit.amount()
    }

    /// Get the sender of this transfer
    pub fn sender(&self) -> PublicKey {
        self.debit.id().actor
    }

    /// Get the credit id of this debit.
    pub fn credit_id(&self) -> Result<CreditId> {
        self.debit.credit_id()
    }
}

/// An Actor cmd.
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct SignedDebit {
    /// The debit.
    pub debit: Debit,
    /// Actor signature over the debit.
    pub actor_signature: Signature,
}

impl SignedDebit {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.debit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.debit.amount()
    }

    /// Get the sender of this transfer
    pub fn sender(&self) -> PublicKey {
        self.debit.sender()
    }

    /// Get the credit id of this debit.
    pub fn credit_id(&self) -> Result<CreditId> {
        self.debit.credit_id()
    }

    /// Tries to represent the signed debit as a share.
    pub fn as_share(&self) -> Result<SignedDebitShare> {
        if let Signature::BlsShare(share) = self.actor_signature.clone() {
            Ok(SignedDebitShare {
                debit: self.debit.clone(),
                actor_signature: share,
            })
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// An Actor cmd.
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct SignedCredit {
    /// The credit.
    pub credit: Credit,
    /// Actor signature over the transfer.
    pub actor_signature: Signature,
}

impl SignedCredit {
    /// Get the credit id
    pub fn id(&self) -> &CreditId {
        self.credit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.credit.amount
    }

    /// Get the sender of this transfer
    pub fn recipient(&self) -> PublicKey {
        self.credit.recipient()
    }

    /// Tries to represent the signed credit as a share.
    pub fn as_share(&self) -> Result<SignedCreditShare> {
        if let Signature::BlsShare(share) = self.actor_signature.clone() {
            Ok(SignedCreditShare {
                credit: self.credit.clone(),
                actor_signature: share,
            })
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

// ------------------------------------------------------------
//                      MULTI SIG
// ------------------------------------------------------------

/// An Actor cmd.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedTransferShare {
    /// The debit.
    debit: SignedDebitShare,
    /// The credit.
    credit: SignedCreditShare,
    ///
    actors: PublicKeySet,
}

impl SignedTransferShare {
    /// Creates a valid transfer share out of its parts.
    pub fn new(
        debit: SignedDebitShare,
        credit: SignedCreditShare,
        actors: PublicKeySet,
    ) -> Result<Self> {
        if debit.amount() != credit.amount() {
            return Err(Error::InvalidOperation);
        }
        if debit.credit_id()? != *credit.id() {
            return Err(Error::InvalidOperation);
        }
        let debit_sig_index = debit.actor_signature.index;
        let credit_sig_index = credit.actor_signature.index;
        if debit_sig_index != credit_sig_index {
            return Err(Error::InvalidOperation);
        }
        Ok(Self {
            debit,
            credit,
            actors,
        })
    }

    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.debit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.debit.amount()
    }

    /// Get the sender of this transfer
    pub fn sender(&self) -> PublicKey {
        self.debit.id().actor
    }

    /// Get the credit id of this debit.
    pub fn credit_id(&self) -> Result<CreditId> {
        self.debit.credit_id()
    }

    /// Get the debit share.
    pub fn debit(&self) -> &SignedDebitShare {
        &self.debit
    }

    /// Get the credit share.
    pub fn credit(&self) -> &SignedCreditShare {
        &self.credit
    }

    /// Get the share index.
    pub fn share_index(&self) -> usize {
        self.debit.actor_signature.index
    }

    /// Get the public key set of the actors.
    pub fn actors(&self) -> &PublicKeySet {
        &self.actors
    }
}

impl Debug for SignedTransferShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedTransferShare {{ debit: {:?}, credit: {:?}, actors: PkSet {{ public_key: {:?} }} }}",
            self.debit,
            self.credit,
            self.actors.public_key()
        )
    }
}

/// An Actor cmd.
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct SignedDebitShare {
    /// The debit.
    pub debit: Debit,
    /// Actor signature over the debit.
    pub actor_signature: SignatureShare,
}

impl SignedDebitShare {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.debit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.debit.amount()
    }

    /// Get the sender of this transfer
    pub fn sender(&self) -> PublicKey {
        self.debit.sender()
    }

    /// Get the credit id of this debit.
    pub fn credit_id(&self) -> Result<CreditId> {
        self.debit.credit_id()
    }

    ///
    pub fn share_index(&self) -> usize {
        self.actor_signature.index
    }
}

/// An Actor cmd.
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct SignedCreditShare {
    /// The credit.
    pub credit: Credit,
    /// Actor signature over the transfer.
    pub actor_signature: SignatureShare,
}

impl SignedCreditShare {
    /// Get the credit id
    pub fn id(&self) -> &CreditId {
        self.credit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.credit.amount
    }

    /// Get the sender of this transfer
    pub fn recipient(&self) -> PublicKey {
        self.credit.recipient()
    }

    ///
    pub fn share_index(&self) -> usize {
        self.actor_signature.index
    }
}

// ------------------------------------------------------------
//                      Replica
// ------------------------------------------------------------

/// Events raised by the Replica.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum ReplicaEvent {
    /// The event raised when
    /// a multisig validation has been proposed.
    TransferValidationProposed(TransferValidationProposed),
    /// The event raised when
    /// ValidateTransfer cmd has been successful.
    TransferValidated(TransferValidated),
    /// The event raised when
    /// RegisterTransfer cmd has been successful.
    TransferRegistered(TransferRegistered),
    /// The event raised when
    /// PropagateTransfer cmd has been successful.
    TransferPropagated(TransferPropagated),
}

/// The debiting Replica event raised when
/// ProposeTransferValidation cmd has been successful.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TransferValidationProposed {
    /// The debit signed by the initiating Actor.
    pub signed_debit: SignedDebitShare,
    /// The credit signed by the initiating Actor.
    pub signed_credit: SignedCreditShare,
    /// When the proposals accumulate, we have an agreed transfer.
    pub agreed_transfer: Option<SignedTransfer>,
}

impl TransferValidationProposed {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.signed_debit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.signed_debit.amount()
    }

    /// Get the sender of this transfer
    pub fn sender(&self) -> PublicKey {
        self.signed_debit.sender()
    }

    /// Get the recipient of this transfer
    pub fn recipient(&self) -> PublicKey {
        self.signed_credit.recipient()
    }
}

/// The debiting Replica event raised when
/// ValidateTransfer cmd has been successful.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferValidated {
    /// The debit initiated by the Actor.
    pub signed_debit: SignedDebit,
    /// The corresponding credit, signed by the Actor.
    pub signed_credit: SignedCredit,
    /// Replica signature over the signed debit.
    pub replica_debit_sig: SignatureShare,
    /// Replica signature over the signed credit.
    pub replica_credit_sig: SignatureShare,
    /// The PK Set of the Replicas
    pub replicas: PublicKeySet,
}

impl Debug for TransferValidated {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransferValidated {{ signed_debit: {:?}, signed_credit: {:?}, replica_debit_sig: {:?}, replica_credit_sig: {:?}, replicas: PkSet {{ public_key: {:?} }} }}",
            self.signed_debit,
            self.signed_credit,
            self.replica_debit_sig,
            self.replica_credit_sig,
            self.replicas.public_key()
        )
    }
}

impl TransferValidated {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.signed_debit.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.signed_debit.amount()
    }

    /// Get the sender of this transfer
    pub fn sender(&self) -> PublicKey {
        self.signed_debit.sender()
    }

    /// Get the recipient of this transfer
    pub fn recipient(&self) -> PublicKey {
        self.signed_credit.recipient()
    }
}

/// The debiting Replica event raised when
/// RegisterTransfer cmd has been successful.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TransferRegistered {
    /// The transfer proof.
    pub transfer_proof: TransferAgreementProof,
}

impl TransferRegistered {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.transfer_proof.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.transfer_proof.amount()
    }

    /// Get the sender of this transfer
    pub fn sender(&self) -> PublicKey {
        self.transfer_proof.sender()
    }

    /// Get the recipient of this transfer
    pub fn recipient(&self) -> PublicKey {
        self.transfer_proof.recipient()
    }
}

/// The crediting Replica event raised when
/// PropagateTransfer cmd has been successful.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TransferPropagated {
    /// The debiting Replicas' proof.
    pub credit_proof: CreditAgreementProof,
}

impl TransferPropagated {
    /// Get the credit id
    pub fn id(&self) -> &CreditId {
        self.credit_proof.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Token {
        self.credit_proof.amount()
    }

    /// Get the recipient of this credit
    pub fn recipient(&self) -> PublicKey {
        self.credit_proof.recipient()
    }
}

/// Public Key Set for a group of transfer replicas.
pub type ReplicaPublicKeySet = PublicKeySet;
/// The Replica event raised when
/// we learn of a new group PK set.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct KnownGroupAdded {
    /// The PublicKeySet of the group.
    pub group: PublicKeySet,
}

impl Debug for KnownGroupAdded {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KnownGroupAdded {{ group: PkSet {{ public_key: {:?} }} }}",
            self.group.public_key()
        )
    }
}

/// Notification of a credit sent to a recipient.
#[derive(Eq, PartialEq, Clone, Serialize, Deserialize, Debug)]
pub struct CreditNotification(pub CreditAgreementProof);