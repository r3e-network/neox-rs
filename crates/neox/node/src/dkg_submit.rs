//! Validator-signed DKG transaction insertion into the local Reth pool.

use crate::{DbftSigner, DbftSignerError, DkgTransactionRequest};
use alloy_primitives::B256;
use reth_ethereum_primitives::TransactionSigned;
use reth_primitives_traits::Recovered;
use reth_transaction_pool::{PoolTransaction, PoolTx, TransactionOrigin, TransactionPool};
use thiserror::Error;

/// Signs a DKG request and inserts it as a trusted local transaction for normal propagation.
pub async fn submit_dkg_pool_transaction<Pool>(
    pool: &Pool,
    signer: &DbftSigner,
    request: DkgTransactionRequest,
) -> Result<B256, DkgTransactionSubmitError>
where
    Pool: TransactionPool,
    PoolTx<Pool>: PoolTransaction<Consensus = TransactionSigned>,
{
    let transaction = signer.sign_dkg_transaction(request)?;
    let recovered = Recovered::new_unchecked(transaction, signer.account());
    let transaction = PoolTx::<Pool>::try_from_consensus(recovered)
        .map_err(|error| DkgTransactionSubmitError::PoolConversion(error.to_string()))?;
    let hash = *transaction.hash();
    pool.add_transaction(TransactionOrigin::Local, transaction)
        .await
        .map_err(|error| DkgTransactionSubmitError::Pool(error.to_string()))?;
    Ok(hash)
}

/// Failure to sign, convert, validate, or insert a DKG transaction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgTransactionSubmitError {
    /// Validator transaction signing or request validation failed.
    #[error(transparent)]
    Signing(#[from] DbftSignerError),
    /// The configured pool transaction type rejected an Ethereum dynamic-fee transaction.
    #[error("failed to convert Neo X DKG transaction for the local pool: {0}")]
    PoolConversion(String),
    /// Normal local-pool validation or insertion failed.
    #[error("failed to submit Neo X DKG transaction to the local pool: {0}")]
    Pool(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use reth_transaction_pool::noop::NoopTransactionPool;

    #[tokio::test]
    async fn signs_and_converts_before_local_pool_insertion() {
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let signer = DbftSigner::from_secret(&secret).unwrap();
        let error = submit_dkg_pool_transaction(
            &NoopTransactionPool::default(),
            &signer,
            DkgTransactionRequest {
                chain_id: 47763,
                nonce: 0,
                gas_limit: 12_000_000,
                max_fee_per_gas: 40_000_000_000,
                max_priority_fee_per_gas: 20_000_000_000,
                calldata: Bytes::from_static(&[0xa8, 0x6e, 0x37, 0xd3]),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, DkgTransactionSubmitError::Pool(_)));
    }
}
