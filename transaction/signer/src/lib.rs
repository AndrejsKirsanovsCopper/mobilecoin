// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Transaction signer types, this defines the API for communication with
//! external reansaction signers, such as the offline signer, or other
//! hardware-backed wallets.
use anyhow::Result;
use clap::Parser;
use log::{debug, info};
use mc_account_keys::AccountKey;
use mc_api::external;
use mc_crypto_ring_signature::KeyImage;
use mc_transaction_core::{onetime_keys::recover_onetime_private_key, tx::TxOut, Amount, TokenId};
use mc_transaction_extra::UnsignedTx;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

use mc_core::keys::TxOutPublic;
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature_signer::{LocalRingSigner, RingSigner};
use mc_transaction_core::{
    ring_ct::{
        Error as RingCtError, ExtendedMessageDigest, InputRing, SignatureRctBulletproofs,
        SigningData,
    },
    tx::Tx,
    TxSummary, UnmaskedAmount,
};
use mc_transaction_summary::TxSummaryUnblindingData;

pub mod types;
use types::*;

pub mod traits;
use traits::*;

/// Command enumeration for offline / detached / hardware signing
#[derive(Clone, PartialEq, Debug, Parser)]
#[non_exhaustive]
pub enum Operations {
    /// Fetch account keys
    GetAccount {
        /// Output file to write view account object
        #[clap(long)]
        output: String,
    },
    /// Sync TXOs, recovering key images for each txo
    SyncTxos {
        /// Input file containing unsynced TxOuts
        #[clap(long)]
        input: String,

        /// Output file to write synced TxOuts
        #[clap(long)]
        output: String,
    },
    /// Sign offline transaction, returning a signed transaction object
    SignTx {
        /// Input file containing transaction for signing
        #[clap(long)]
        input: String,

        /// Output file to write signed transaction
        #[clap(long)]
        output: String,
    },
    /// Sign offline transaction, returning a signed transaction object
    SignUnsignedTx {
        /// Input file containing transaction for signing
        #[clap(long)]
        input: String,

        /// Output file to write signed transaction
        #[clap(long)]
        output: String,
    },
}

impl Operations {
    /// Fetch account index for a given command
    pub fn account_index(&self) -> u32 {
        0
    }

    /// Fetch view account credentials
    ///
    /// output - file to write view account information
    pub fn get_account(
        ctx: impl ViewAccountProvider,
        account_index: u32,
        output: &str,
    ) -> anyhow::Result<()> {
        debug!("Loading view account keys");
        let keys = match ctx.account() {
            Ok(v) => v,
            Err(e) => return Err(anyhow::anyhow!("Failed to load view account keys: {:?}", e)),
        };

        let info = AccountInfo {
            account_index,
            view_private: keys.view_private_key().clone(),
            spend_public: keys.spend_public_key().clone(),
        };

        debug!("Writing view account information to: {}", output);
        write_output(output, &info)?;

        Ok(())
    }

    /// Sync TxOuts
    ///
    /// input - file containing a list of subaddress indices and
    /// tx_out_public_keys output - file to write list of tx_out_public_keys
    /// and resolved key_images
    pub fn sync_txos(ctx: impl KeyImageComputer, input: &str, output: &str) -> anyhow::Result<()> {
        // Load unsynced txout_public_key pairs
        debug!("Reading unsynced TxOuts from '{}'", input);
        let req: TxoSyncReq = read_input(input)?;

        // Compute key images
        // Since we're provided with a subaddress index,
        // assume TxOut ownership is correct.
        let mut synced: Vec<TxoSynced> = Vec::new();
        for TxoUnsynced {
            subaddress,
            tx_out_public_key,
        } in req.txos
        {
            let key_image = match ctx.compute_key_image(subaddress, &tx_out_public_key) {
                Ok(v) => v,
                Err(e) => return Err(anyhow::anyhow!("Failed to compute key image: {:?}", e)),
            };

            synced.push(TxoSynced {
                tx_out_public_key: tx_out_public_key.clone(),
                key_image,
            });
        }

        let resp = TxoSyncResp {
            account_id: req.account_id,
            synced_txos: synced,
        };

        // Write matched key images
        debug!("Writing synced TxOuts to '{}'", output);
        write_output(output, &resp)?;

        Ok(())
    }

    /// Sync an unsigned transaction
    ///
    /// input - file containing the unsigned transaction object
    /// output - file to write the signed transaction output
    pub fn sign_tx(ctx: impl RingSigner, input: &str, output: &str) -> anyhow::Result<()> {
        // Load unsigned transaction object
        debug!("Reading unsigned transaction from '{}'", input);
        let req: TxSignReq = read_input(input)?;

        // Sign transaction
        let prefix = req.tx_prefix.clone();
        let signature = match SignatureRctBulletproofs::sign(
            req.block_version,
            &prefix,
            req.rings.as_slice(),
            &req.output_secrets(),
            Amount::new(prefix.fee, TokenId::from(prefix.fee_token_id)),
            &ctx,
            &mut OsRng {},
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to sign transaction: {:?}", e));
            }
        };

        // Map key images to real inputs via public key
        let mut txos = vec![];
        for (i, r) in req.rings.iter().enumerate() {
            let tx_out_public_key = match r {
                InputRing::Signable(r) => r.members[r.real_input_index].public_key,
                InputRing::Presigned(_) => panic!("Pre-signed rings unsupported"),
            };

            txos.push(TxoSynced {
                tx_out_public_key: TxOutPublic::from(
                    RistrettoPublic::try_from(&tx_out_public_key).unwrap(),
                ),
                key_image: signature.ring_signatures[i].key_image,
            });
        }

        let resp = TxSignResp {
            account_id: req.account_id,
            tx: Tx {
                prefix,
                signature,
                fee_map_digest: vec![],
            },
            txos,
        };

        // Write signed transaction output
        debug!("Writing signed transaction to '{}'", output);
        write_output(output, &resp)?;

        Ok(())
    }

    pub fn sign_unsigned_tx(
        account_key: AccountKey,
        input: &str,
        output: &str,
    ) -> anyhow::Result<()> {
        // Load unsigned transaction object
        info!("Reading unsigned transaction from '{}'", input);
        // let req: TxSignReq = read_input(input)?;
        let unsigned_tx_proposal_wrapper: UnsignedTxProposalWrapper = read_input(input)?;
        let unsigned_proposal = unsigned_tx_proposal_wrapper.unsigned_tx_proposal;

        info!(
            "Loaded unsigned tx proposal with {} inputs",
            unsigned_proposal.unsigned_input_txos.len()
        );
        // Decode the unsigned tx protobuf
        let unsigned_tx_bytes = hex::decode(&unsigned_proposal.unsigned_tx_proto_bytes_hex)
            .map_err(|e| anyhow::anyhow!("Failed to decode unsigned_tx_proto_bytes_hex: {}", e))?;

        let unsigned_tx_proto: external::UnsignedTx = mc_util_serial::decode(&unsigned_tx_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to decode UnsignedTx protobuf: {}", e))?;

        let unsigned_tx: UnsignedTx = (&unsigned_tx_proto)
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert UnsignedTx: {:?}", e))?;

        println!("Decoded unsigned transaction");

        // Process input TXOs and compute key images
        let mut input_txos = Vec::new();
        for input in &unsigned_proposal.unsigned_input_txos {
            let tx_out_bytes = hex::decode(&input.tx_out_proto)
                .map_err(|e| anyhow::anyhow!("Failed to decode tx_out_proto: {}", e))?;
            let tx_out: TxOut = mc_util_serial::decode(&tx_out_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to decode TxOut protobuf: {}", e))?;

            let subaddress_index: u64 = input
                .subaddress_index
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid subaddress_index: {}", e))?;

            // Compute key image
            let tx_out_public_key =
                mc_crypto_keys::RistrettoPublic::try_from(&tx_out.public_key)
                    .map_err(|e| anyhow::anyhow!("Invalid tx_out public key: {:?}", e))?;

            let onetime_private_key = recover_onetime_private_key(
                &tx_out_public_key,
                account_key.view_private_key(),
                &account_key.subaddress_spend_private(subaddress_index),
            );

            let key_image = KeyImage::from(&onetime_private_key);

            input_txos.push(InputTxoJson {
                tx_out_proto: input.tx_out_proto.clone(),
                tx_out_public_key: input.tx_out_public_key.clone(),
                subaddress_index: input.subaddress_index.clone(),
                key_image: hex::encode(key_image.as_ref() as &[u8]),
                amount: input.amount.clone(),
            });
        }

        info!("Computed {} key images", input_txos.len());

        // Sign the transaction
        let signer = LocalRingSigner::from(&account_key);
        let mut rng = rand::thread_rng();
        let signed_tx = unsigned_tx
            .sign(&signer, None, &mut rng)
            .map_err(|e| anyhow::anyhow!("Failed to sign transaction: {:?}", e))?;

        println!("Transaction signed successfully!");

        // Encode signed transaction
        let tx_bytes = mc_util_serial::encode(&signed_tx);
        let tx_proto_hex = hex::encode(&tx_bytes);

        // Build output
        let signed_proposal = SignedTxProposalJson {
            tx_proto: tx_proto_hex,
            input_txos,
            payload_txos: unsigned_proposal.payload_txos.clone(),
            change_txos: unsigned_proposal.change_txos.clone(),
        };

        let output_json = OutputJson {
            method: "sign_tx".to_string(),
            params: SignedTxProposalResult {
                tx_proposal: signed_proposal,
            },
            jsonrpc: "2.0".to_string(),
            id: 1,
        };

        // Write output
        let output_json_string = serde_json::to_string_pretty(&output_json)
            .map_err(|e| anyhow::anyhow!("Failed to serialize output: {}", e))?;

        write_output(output, &output_json)?;
        // fs::write(&args.output, &output_json)
        //     .map_err(|e| anyhow!("Failed to write output file: {}", e))?;

        info!("Signed transaction written to: {}", output);

        Ok(())
    }
}

/// Helper to read and deserialize input files
pub fn read_input<T: DeserializeOwned>(file_name: &str) -> anyhow::Result<T> {
    debug!("Reading input from '{}'", file_name);

    let s = std::fs::read_to_string(file_name)?;

    // Determine format from file name
    let p = Path::new(file_name);

    // Decode based on input extension
    let v = match p.extension().and_then(|e| e.to_str()) {
        // Encode to JSON for `.json` files
        Some("json") => serde_json::from_str(&s)?,
        _ => return Err(anyhow::anyhow!("unsupported output file format")),
    };

    Ok(v)
}

/// Helper to serialize and write output files
pub fn write_output(file_name: &str, value: &impl Serialize) -> anyhow::Result<()> {
    debug!("Writing output to '{}'", file_name);

    // Determine format from file name
    let p = Path::new(file_name);
    match p.extension().and_then(|e| e.to_str()) {
        // Encode to JSON for `.json` files
        Some("json") => {
            let s = serde_json::to_string(value)?;
            std::fs::write(p, s)?;
        }
        _ => return Err(anyhow::anyhow!("unsupported output file format")),
    }

    Ok(())
}

impl TxSignReq {
    /// Get prepared (but unsigned) ringct bulletproofs for later signing,
    /// note only one instance of this must be used between operations.
    pub fn get_signing_data<RNG: CryptoRng + RngCore>(
        &self,
        rng: &mut RNG,
    ) -> Result<
        (
            SigningData,
            TxSummary,
            Option<TxSummaryUnblindingData>,
            ExtendedMessageDigest,
        ),
        RingCtError,
    > {
        let fee_amount = Amount::new(
            self.tx_prefix.fee,
            TokenId::from(self.tx_prefix.fee_token_id),
        );
        let (signing_data, tx_summary, extended_message_digest) = SigningData::new_with_summary(
            self.block_version,
            &self.tx_prefix,
            &self.rings,
            &self.output_secrets(),
            fee_amount,
            true,
            rng,
        )?;

        let mut tx_summary_unblinding_data = None;

        // Try to build the TxSummary unblinding data, which requires the amounts from
        // the rings, and the blinding factors from the signing data segment.
        if let TxSignSecrets::TxOutUnblindingData(tx_out_unblinding_data) = &self.secrets {
            if signing_data.pseudo_output_blindings.len() != self.rings.len() {
                return Err(RingCtError::LengthMismatch(
                    signing_data.pseudo_output_blindings.len(),
                    self.rings.len(),
                ));
            }

            tx_summary_unblinding_data = Some(TxSummaryUnblindingData {
                block_version: *self.block_version,
                outputs: tx_out_unblinding_data.clone(),
                inputs: signing_data
                    .pseudo_output_blindings
                    .iter()
                    .zip(self.rings.iter())
                    .map(|(blinding, ring)| {
                        let amount = ring.amount();
                        UnmaskedAmount {
                            value: amount.value,
                            token_id: *amount.token_id,
                            blinding: (*blinding).into(),
                        }
                    })
                    .collect(),
            });
        }

        Ok((
            signing_data,
            tx_summary,
            tx_summary_unblinding_data,
            extended_message_digest,
        ))
    }
}
