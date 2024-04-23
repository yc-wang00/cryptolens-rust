

<h1 align="center">Cryptolens Rust Client</h1>

<p align="center">
  <img alt="Github top language" src="https://img.shields.io/github/languages/top/yc-wang00/cryptolens-rust?color=56BEB8">

  <img alt="Github language count" src="https://img.shields.io/github/languages/count/yc-wang00/cryptolens-rust?color=56BEB8">

  <img alt="Repository size" src="https://img.shields.io/github/repo-size/yc-wang00/cryptolens-rust?color=56BEB8">

  <!-- <img alt="License" src="https://img.shields.io/github/license/yc-wang00/cryptolens-rust?color=56BEB8"> -->

  <!-- <img alt="Github issues" src="https://img.shields.io/github/issues/yc-wang00/cryptolens-rust?color=56BEB8" /> -->

  <!-- <img alt="Github forks" src="https://img.shields.io/github/forks/yc-wang00/cryptolens-rust?color=56BEB8" /> -->

  <!-- <img alt="Github stars" src="https://img.shields.io/github/stars/yc-wang00/cryptolens-rust?color=56BEB8" /> -->
</p>

## Contents

- [Contents](#contents)
- [About](#about)
- [Installation](#installation)
- [Usage](#usage)
  - [Example](#example)
    - [Basic usage example](#basic-usage-example)
    - [Offline validation example:](#offline-validation-example)
- [Contributions](#contributions)
- [License](#license)




## About

This crate provides helper functions for managing and verifying license keys using Cryptolens. It simplifies the process of key activations, validations, and also offers utilities for handling RSA keys for digital signatures.


**Why I make this crate?** 


In the official Cryptolens GitHub repository, there is an existing cryptolens-rust crate, but its last update was 5 years ago (2019), and it appears that some of its functionality may no longer be working correctly. Since there were no up-to-date alternatives available for using Cryptolens with Rust, I created this crate to provide a maintained and functioning solution for the Rust community.


**04/23/2024 Updated 0.2.0 add offline validation function and example**

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cryptolens_yc = "0.2.0"
```

## Usage

To start using the `cryptolens_yc` crate, you need to include it in your Rust project and use the provided functions to activate and validate license keys.

### Example

#### Basic usage example
Here is a basic example demonstrating how to activate a license key and verify its signature:

```rust
use cryptolens_yc::{key_activate, KeyActivateArguments};

let public_key = "<RSAKeyValue><Modulus>...</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
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
```

This example shows how to activate a license and check if the returned license has a valid signature with the given public RSA key.

#### Offline validation example: 

```rust
// get the license key from above code ...

// save the license key to a file
let path = "cached_license_key";
save_license_key_to_file(&license_key, path)?;

// you can also load the license key from a file
let loaded_license_key = cryptolens_yc::load_license_key_from_file(path)?;

// validate the loaded license key
match loaded_license_key.has_valid_signature(public_key) {
    Ok(valid) => assert_eq!(valid, true),
    Err(e) => panic!("Error: {}", e),
}
```


## Contributions

Contributions are welcome! Please fork the repository and open a pull request with your changes.


## License

This project is under license from MIT. For more details, see the [LICENSE](LICENSE) file.


&#xa0;

<a href="#top">Back to top</a>

