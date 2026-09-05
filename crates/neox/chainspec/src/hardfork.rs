use reth_chainspec::hardfork;

hardfork!(
    /// Neo X-specific protocol hardforks.
    ///
    /// Ethereum hardforks remain represented by `EthereumHardfork`; these variants only model
    /// consensus and execution changes introduced by Neo X.
    NeoXHardfork {
        /// Enables DKG system contracts, precompiles, and associated execution rules.
        Dkg,
        /// Enables threshold-encrypted Envelope transactions and Anti-MEV consensus behavior.
        AntiMev,
        /// Switches dBFT block seals to the Ethereum-compatible signature scheme.
        EthSignature,
        /// Enforces strict PKCS#7 unpadding for threshold-decrypted Anti-MEV payloads.
        Pkcs7Strict,
    }
);
