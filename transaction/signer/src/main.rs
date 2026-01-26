// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Offline transaction signer implementation
//!
//! WIP port / simplification from https://github.com/mobilecoinofficial/full-service/blob/fefe6f645d676b393ece2f607f0081304141b590/transaction-signer/src/bin/main.rs#L337

use anyhow::anyhow;
use bip39::{Language, Mnemonic, MnemonicType};
use clap::Parser;
use log::info;
use mc_common::logger::{create_app_logger, o};
use mc_crypto_keys::RistrettoPrivate;
use serde::{Deserialize, Serialize};

use mc_core::{
    account::{self, Account},
    keys::{RootSpendPrivate, RootViewPrivate},
    slip10::Slip10KeyGenerator,
};
use mc_crypto_ring_signature_signer::LocalRingSigner;
use mc_transaction_core::AccountKey;
use mc_transaction_signer::{read_input, write_output, Operations};
// use rand::{thread_rng, RngCore};

#[derive(Clone, PartialEq, Debug, Parser)]
struct Args {
    /// Account secrets file
    #[clap(long, short, default_value = "mc_secrets.json")]
    secret_file: String,

    #[command(subcommand)]
    action: Actions,
}

#[derive(Clone, PartialEq, Debug, Parser)]
enum Actions {
    /// Create a new offline account, writing secrets to the output file
    Create {
        /// Optional account name
        #[clap(short, long)]
        name: Option<String>,

        /// File name for account secrets to be written to
        #[clap(short, long)]
        output: String,
    },
    /// Import an existing offline account via mnemonic
    Import {
        /// Optional account name
        #[clap(short, long)]
        name: Option<String>,

        /// File for account secrets to be written to
        #[clap(short, long)]
        output: String,
    },

    // Implement shared signer commands
    #[command(flatten)]
    Signer(Operations),
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct AccountSecrets {
    mnemonic: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct AccountPrivateKeys {
    spend_private_key: String,
    view_private_key: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct AccountImport {
    name: Option<String>,
    spend_public_key: String,
    view_private_key: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct AccountImportFile {
    params: AccountImport,
}

fn main() -> anyhow::Result<()> {
    // Initialize logger
    let _logger = create_app_logger(o!());

    // Parse command line arguments
    let args = Args::parse();

    // Run commands
    match &args.action {
        Actions::Create { output, name } | Actions::Import { output, name, .. } => {
            let account = match &args.action {
                Actions::Import { .. } => {
                    let private_keys: AccountPrivateKeys = read_input(&args.secret_file)?;
                    account_from_private_keys(private_keys)
                }
                _ => {
                    let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
                    let slip10key = mnemonic.derive_slip10_key(0);

                    // Generate account from secrets
                    let account = Account::from(&slip10key);
                    account
                }
            };
            let s = AccountImportFile {
                params: AccountImport {
                    name: name.clone(),
                    spend_public_key: hex::encode(account.spend_public_key().to_bytes()),
                    view_private_key: hex::encode(account.view_private_key().as_ref()),
                },
            };

            // Otherwise write out new secrets
            write_output(output, &s)?;

            info!("Account secrets written to '{}'", output);
        }
        Actions::Signer(c) => {
            // Load account secrets
            info!("Account secrets written to '{}'", c.account_index());

            let private_keys: AccountPrivateKeys = read_input(&args.secret_file)?;
            let a = account_from_private_keys(private_keys);
            let account_index = c.account_index();

            // Handle standard commands
            match c {
                Operations::GetAccount { output, .. } => {
                    Operations::get_account(&a, account_index, output)?
                }
                Operations::SyncTxos { input, output, .. } => {
                    Operations::sync_txos(&a, input, output)?
                }
                Operations::SignTx { input, output, .. } => {
                    // Setup local ring signer
                    let ring_signer = LocalRingSigner::from(&AccountKey::new(
                        a.spend_private_key().as_ref(),
                        a.view_private_key().as_ref(),
                    ));

                    // Perform transaction signing
                    Operations::sign_tx(&ring_signer, input, output)?;
                }
                Operations::SignUnsignedTx { input, output, .. } => {
                    let account_key = AccountKey::new(
                        a.spend_private_key().as_ref(),
                        a.view_private_key().as_ref(),
                    );
                    // Perform transaction signing
                    Operations::sign_unsigned_tx(account_key, input, output)?;
                }
                _ => (),
            }
        }
    }

    Ok(())
}

fn account_from_private_keys(account_private_keys: AccountPrivateKeys) -> Account {
    // Decode spend private key
    let mut spend_bytes = [0u8; 32];
    hex::decode_to_slice(account_private_keys.spend_private_key, &mut spend_bytes)
        .map_err(|e| anyhow!("Invalid spend_private_key hex: {}", e));
    let spend_private_key: RistrettoPrivate = (&spend_bytes)
        .try_into()
        .map_err(|_| anyhow!("Invalid spend_private_key bytes - not a valid scalar"))
        .unwrap();

    // Decode view private key
    let mut view_bytes = [0u8; 32];
    hex::decode_to_slice(account_private_keys.view_private_key, &mut view_bytes)
        .map_err(|e| anyhow!("Invalid view_private_key hex: {}", e));
    let view_private_key: RistrettoPrivate = (&view_bytes)
        .try_into()
        .map_err(|_| anyhow!("Invalid view_private_key bytes - not a valid scalar"))
        .unwrap();

    let root_view_private = RootViewPrivate::from(view_private_key);
    let root_spend_private = RootSpendPrivate::from(spend_private_key);

    return Account::new(root_view_private, root_spend_private);
}
