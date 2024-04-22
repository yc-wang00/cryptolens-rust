//! # Cryptolens Rust Client
//!
//! This crate provides helper function for managing and verifying license keys using cryptolens.
//! It handles key activations, validations, and provides utilities for working with RSA keys for
//! digital signatures.
//!
//! ## Examples
//!
//! Basic usage:
//!
//! ```
//! 
//! use cryptolens_yc::{key_activate, KeyActivateArguments};
//! // this is the example in original documentation
//! let public_key = "<RSAKeyValue><Modulus>khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
//! 
//! let product_id = "3646";
//! let key = "MPDWY-PQAOW-FKSCH-SGAAU";
//! let token = "WyI0NjUiLCJBWTBGTlQwZm9WV0FyVnZzMEV1Mm9LOHJmRDZ1SjF0Vk52WTU0VzB2Il0=";
//! 
//! let license_key = key_activate(
//!     token,
//!     KeyActivateArguments {
//!         ProductId: product_id.parse().unwrap(),
//!         Key: key.to_string(),
//!         MachineCode: "289jf2afs3".to_string(),
//!         ..Default::default()
//!     },
//! ).unwrap();
//! 
//! match license_key.has_valid_signature(public_key) {
//!     Ok(valid) => assert_eq!(valid, true),
//!     Err(e) => panic!("Error: {}", e),
//! }
//! 
//! ```
//! 

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_xml_rs;

/// Represents an RSA key value pair with modulus and exponent.
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct RSAKeyValue {
    Modulus: String,
    Exponent: String,
}

/// Customer information associated with a license key.
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Customer {
    pub Id: u64,
    pub Name: String,
    pub Email: String,
    pub CompanyName: String,
    pub Created: u64,
}

/// Represents data about an activation instance.
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct ActivationData {
    pub Mid: String,
    pub IP: String,
    pub Time: u64,
}

/// A data object that can store custom information.
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct DataObject {
    pub Id: u64,
    pub Name: String,
    pub StringValue: String,
    pub IntValue: u64,
}

/// Arguments used to activate a product key.
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct KeyActivateArguments {
    pub ProductId: u64,
    pub Key: String,
    pub MachineCode: String,
    pub FriendlyName: String,
    pub FieldsToReturn: u8,
    pub SignMethod: u8,
    pub FloatingTimeInterval: u64,
    pub MaxOverdraft: u64,
    pub Metadata: bool,
    pub OSInfo: String,
    pub ModelVersion: u8,
    pub v: u8,
}

impl Default for KeyActivateArguments {
    fn default() -> Self {
        KeyActivateArguments {
            ProductId: 0,
            Key: "".to_string(),
            MachineCode: "".to_string(),
            FriendlyName: "".to_string(),
            FieldsToReturn: 0,
            SignMethod: 1,
            FloatingTimeInterval: 0,
            MaxOverdraft: 0,
            Metadata: false,
            OSInfo: "".to_string(),
            ModelVersion: 1,
            v: 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct SerdeLicenseKey {
    ProductId: u64,
    Id: Option<u64>,
    Key: Option<String>,
    Created: u64,
    Expires: u64,
    Period: u64,
    F1: bool,
    F2: bool,
    F3: bool,
    F4: bool,
    F5: bool,
    F6: bool,
    F7: bool,
    F8: bool,
    Notes: Option<String>,
    Block: bool,
    GlobalId: Option<u64>,
    Customer: Option<Customer>,
    ActivatedMachines: Vec<ActivationData>,
    TrialActivation: bool,
    MaxNoOfMachines: Option<u64>,
    AllowedMachines: Option<String>,
    DataObjects: Vec<DataObject>,
    SignDate: u64,
}

/// Represents a license key in cryptolens format.
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct LicenseKey {
    pub ProductId: u64,
    pub Id: Option<u64>,
    pub Key: Option<String>,
    pub Created: u64,
    pub Expires: u64,
    pub Period: u64,
    pub F1: bool,
    pub F2: bool,
    pub F3: bool,
    pub F4: bool,
    pub F5: bool,
    pub F6: bool,
    pub F7: bool,
    pub F8: bool,
    pub Notes: Option<String>,
    pub Block: bool,
    pub GlobalId: Option<u64>,
    pub Customer: Option<Customer>,
    pub ActivatedMachines: Vec<ActivationData>,
    pub TrialActivation: bool,
    pub MaxNoOfMachines: Option<u64>,
    pub AllowedMachines: Vec<String>,
    pub DataObjects: Vec<DataObject>,
    pub SignDate: u64,

    license_key_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
}


/// Represents the response from an activation request.
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct ActivateResponse {
    result: i8,
    message: String,
    licenseKey: String,
    signature: Option<String>,
}

impl LicenseKey {
    /// Constructs a `LicenseKey` from a JSON string containing activation response data.
    ///
    /// # Arguments
    /// * `s` - A string slice that holds the JSON data to parse.
    ///
    /// # Errors
    /// Returns an error if parsing fails or if base64 decoding is unsuccessful.
    pub fn from_str(s: &str) -> anyhow::Result<LicenseKey> {
        let activate_response: ActivateResponse = serde_json::from_str(&s)?;

        let license_key = activate_response.licenseKey;
        let signature = activate_response.signature;

        let license_key_bytes = BASE64_STANDARD.decode(&license_key)?;
        let signature_bytes = BASE64_STANDARD.decode(&signature.unwrap())?;

        let license_key_string = String::from_utf8(license_key_bytes.clone())?;
        let serde_lk: SerdeLicenseKey = serde_json::from_str(&license_key_string)?;

        Ok(LicenseKey {
            ProductId: serde_lk.ProductId,
            Id: serde_lk.Id,
            Key: serde_lk.Key,
            Created: serde_lk.Created,
            Expires: serde_lk.Expires,
            Period: serde_lk.Period,
            F1: serde_lk.F1,
            F2: serde_lk.F2,
            F3: serde_lk.F3,
            F4: serde_lk.F4,
            F5: serde_lk.F5,
            F6: serde_lk.F6,
            F7: serde_lk.F7,
            F8: serde_lk.F8,
            Notes: serde_lk.Notes,
            Block: serde_lk.Block,
            GlobalId: serde_lk.GlobalId,
            Customer: serde_lk.Customer,
            ActivatedMachines: serde_lk.ActivatedMachines,
            TrialActivation: serde_lk.TrialActivation,
            MaxNoOfMachines: serde_lk.MaxNoOfMachines,
            AllowedMachines: serde_lk
                .AllowedMachines
                .map(|s| s.split('\n').map(|x| x.to_string()).collect())
                .unwrap_or_else(Vec::new),
            DataObjects: serde_lk.DataObjects,
            SignDate: serde_lk.SignDate,

            license_key_bytes: license_key_bytes,
            signature_bytes: signature_bytes,
        })
    }

    /// Verifies the validity of the digital signature associated with this license key.
    ///
    /// # Arguments
    /// * `public_key` - A string slice containing the public key in XML format used to verify the signature.
    ///
    /// # Returns
    /// Returns `true` if the signature is valid, otherwise returns `false`.
    ///
    /// # Errors
    /// Returns an error if any cryptographic operations fail during verification.
    pub fn has_valid_signature(&self, public_key: &str) -> anyhow::Result<bool> {
        let public_key: RSAKeyValue = serde_xml_rs::from_str(public_key)?;

        let modulus_bytes = BASE64_STANDARD.decode(&public_key.Modulus)?;
        let exponent_bytes = BASE64_STANDARD.decode(&public_key.Exponent)?;

        let modulus = openssl::bn::BigNum::from_slice(&modulus_bytes)?;
        let exponent = openssl::bn::BigNum::from_slice(&exponent_bytes)?;

        let keypair = openssl::rsa::Rsa::from_public_components(modulus, exponent)?;
        let keypair = openssl::pkey::PKey::from_rsa(keypair)?;

        let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &keypair)?;

        verifier.update(&self.license_key_bytes)?;
        let valid = verifier.verify(&self.signature_bytes)?;
        Ok(valid)
    }
}

pub fn key_activate(token: &str, args: KeyActivateArguments) -> anyhow::Result<LicenseKey> {
    // Create a new reqwest client (blocking)
    let client = reqwest::blocking::Client::new();
    let params = [
        ("token", token),
        ("ProductId", &args.ProductId.to_string()),
        ("Key", &args.Key),
        ("MachineCode", &args.MachineCode),
        ("FriendlyName", &args.FriendlyName),
        ("FieldsToReturn", &args.FieldsToReturn.to_string()),
        ("SignMethod", &args.SignMethod.to_string()),
        ("FloatingTimeInterval", &args.FloatingTimeInterval.to_string()),
        ("MaxOverdraft", &args.MaxOverdraft.to_string()),
        ("Metadata", &args.Metadata.to_string()),
        ("OSInfo", &args.OSInfo),
        ("ModelVersion", &args.ModelVersion.to_string()),
        ("v", &args.v.to_string()),
        ("Sign", "true"),
    ];

    let res = client
        .post("https://app.cryptolens.io/api/key/Activate")
        .form(&params)
        .send()?;
    let s = res.text()?;

    // Check if result is an error, if so, return an error
    let response: serde_json::Value = serde_json::from_str(&s)?;
    if response["result"] != 0 {
        return Err(anyhow::anyhow!(
            "Error Info: result: {}, message: {}",
            response["result"],
            response["message"]
        ));
    }

    // otherwise, return the license key
    LicenseKey::from_str(&s)
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_key_activate() {
        // this is the example in original documentation
        let public_key = "<RSAKeyValue><Modulus>khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        let product_id = "3646";
        let key = "MPDWY-PQAOW-FKSCH-SGAAU";
        let token = "WyI0NjUiLCJBWTBGTlQwZm9WV0FyVnZzMEV1Mm9LOHJmRDZ1SjF0Vk52WTU0VzB2Il0=";

        let license_key = key_activate(
            token,
            KeyActivateArguments {
                ProductId: product_id.parse().unwrap(),
                Key: key.to_string(),
                MachineCode: "289jf2afs3".to_string(),
                ..Default::default()
            },
        ).unwrap();

        match license_key.has_valid_signature(public_key) {
            Ok(valid) => assert_eq!(valid, true),
            Err(e) => panic!("Error: {}", e),
        }
    }
}
