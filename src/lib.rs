// extern crate bitcoin;



extern crate core;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::hashes::hex::{FromHex, ToHex};
    use bitcoin::{Address, OutPoint, schnorr, SchnorrSighashType, Transaction, Txid, TxIn, TxOut, Witness};
    use bitcoin::hashes::{Hash, HashEngine};
    use bitcoin::psbt::serialize::Serialize;
    use bitcoin::schnorr::{TapTweak, UntweakedKeyPair};
    use bitcoin::Script;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::util::taproot;
    use secp256k1::{Message};

    #[test]
    fn create_treeless_output_and_transaction() {
        // DANGER
        let secp = Secp256k1::new();
        let private_key_slice: Vec<u8> = FromHex::from_hex("abbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        let private_key = bitcoin::KeyPair::from_seckey_slice(&secp, &private_key_slice).unwrap();
        let internal_key = private_key.public_key();
        assert_eq!(internal_key.to_hex(), "2761f9195825a851875350e5f248a6ee770e81a5686ccdaa9765fe714a16123f");

        let builder = taproot::TaprootBuilder::new();
        let tap_tree = builder.finalize(&secp, internal_key).unwrap();

        let output_details = Address::p2tr(&secp, internal_key, tap_tree.merkle_root(), bitcoin::Network::Regtest);
        let address = output_details.to_string();
        let output_script = output_details.script_pubkey().to_hex();
        assert_eq!(address, "bcrt1pekm6vrlsqnwctfa2scktz59qc7hkn6j3kfjwaes09tydu24yxres39hnp6");
        assert_eq!(output_script, "5120cdb7a60ff004dd85a7aa862cb150a0c7af69ea51b264eee60f2ac8de2aa430f3");

        let previous_output = OutPoint::new(Txid::from_hex("991ab2b13f6bc6c13002d79d5e9775626a5e7328e14cd16837d50d1cc637dc6a").unwrap(), 0);
        let tx_input = TxIn {
            previous_output,
            script_sig: Default::default(),
            sequence: 0xffffffff,
            witness: Default::default()
        };

        let tx_output = TxOut {
            value: 4999995000,
            script_pubkey: output_details.script_pubkey()
        };

        let mut transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![tx_input],
            output: vec![tx_output]
        };

        // SIGHASH_DEFAULT is 0
        let signature_hash = transaction.signature_hash(0, &output_details.script_pubkey(), 0);
        let message = Message::from_slice(&signature_hash.to_vec()).unwrap();
        println!("sighash: {}", message.to_hex());

        let tweaked_private_key = private_key.tap_tweak(&secp, tap_tree.merkle_root()).into_inner();
        let signature = tweaked_private_key.sign_schnorr(message);
        let signature_vec = signature.as_ref().to_vec();

        transaction.input[0].witness = Witness::from_vec(vec![signature_vec]);

        let transaction_hex = transaction.serialize().to_hex();
        println!("transaction hex: {}", transaction_hex);
    }

    #[test]
    fn create_test_vector_branch() {
        let builder = taproot::TaprootBuilder::new();
        let script = Script::from_hex("20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac").unwrap();
        let builder = builder.add_leaf(0, script.clone()).unwrap();

        let secp = Secp256k1::verification_only();
        let internal_key = schnorr::UntweakedPublicKey::from_str("93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820").unwrap();
        let tap_tree = builder.finalize(&secp, internal_key).unwrap();

        let output_details = Address::p2tr(&secp, internal_key, tap_tree.merkle_root(), bitcoin::Network::Regtest);
        let address = output_details.to_string();
        let output_script = output_details.script_pubkey().to_hex();
        assert_eq!(address, "bcrt1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58q6cq58p");
        assert_eq!(output_script, "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e");

        let versioned_script = (script, taproot::LeafVersion::TapScript);
        let control = tap_tree.control_block(&versioned_script).unwrap().serialize().to_hex();
        assert_eq!(control, "c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820");
    }

    #[test]
    fn create_test_vector_tree() {
        let builder = taproot::TaprootBuilder::new();

        /*
        – <Root> (depth 0)
            – A (depth 1)
            – <Branch> (depth 1)
                – B (depth 2)
                – C (depth 2)
         */

        let script_a = Script::from_hex("2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac").unwrap();
        let script_b = Script::from_hex("20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac").unwrap();
        let script_c = Script::from_hex("20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac").unwrap();

        // add leaves in depth-first order
        let builder = builder.add_leaf(1, script_a.clone()).unwrap();
        let builder = builder.add_leaf(2, script_b.clone()).unwrap();
        let builder = builder.add_leaf(2, script_c.clone()).unwrap();

        let secp = Secp256k1::verification_only();
        let internal_key = schnorr::UntweakedPublicKey::from_str("55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d").unwrap();
        let tap_tree = builder.finalize(&secp, internal_key).unwrap();

        let output_details = Address::p2tr(&secp, internal_key, tap_tree.merkle_root(), bitcoin::Network::Regtest);
        let address = output_details.to_string();
        let output_script = output_details.script_pubkey().to_hex();
        assert_eq!(address, "bcrt1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcs24qspv");
        assert_eq!(output_script, "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831");

        let versioned_script_a = (script_a, taproot::LeafVersion::TapScript);
        let versioned_script_b = (script_b, taproot::LeafVersion::TapScript);
        let versioned_script_c = (script_c, taproot::LeafVersion::TapScript);

        let control_a = tap_tree.control_block(&versioned_script_a).unwrap().serialize().to_hex();
        let control_b = tap_tree.control_block(&versioned_script_b).unwrap().serialize().to_hex();
        let control_c = tap_tree.control_block(&versioned_script_c).unwrap().serialize().to_hex();

        assert_eq!(control_a, "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91");
        assert_eq!(control_b, "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312dd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d");
        assert_eq!(control_c, "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d");
    }

    #[test]
    fn create_preimage_tapscript() {
        let hash_reference_preimage = b"arik";
        let mut hash_reference = bitcoin::hashes::hash160::Hash::hash(&hash_reference_preimage[..]).to_hex();
        assert_eq!(hash_reference, "da3ae579ab6e7dbbf607b3096e32b0f15fb33a33");

        // note that da3ae579ab6e7dbbf607b3096e32b0f15fb33a33 is a substring of the script below
        // OP_DUP (0x76) OP_HASH160 (0xa9) <20 bytes (0x14)> da3ae579ab6e7dbbf607b3096e32b0f15fb33a33 OP_EQUALVERIFY (0x88)
        let script = Script::from_hex("76a914da3ae579ab6e7dbbf607b3096e32b0f15fb33a3388").unwrap();

        let builder = taproot::TaprootBuilder::new();
        let builder = builder.add_leaf(0, script.clone()).unwrap();

        let secp = Secp256k1::new();
        let private_key_slice: Vec<u8> = FromHex::from_hex("abbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        let private_key = bitcoin::KeyPair::from_seckey_slice(&secp, &private_key_slice).unwrap();
        let internal_key = private_key.public_key();
        assert_eq!(internal_key.to_hex(), "2761f9195825a851875350e5f248a6ee770e81a5686ccdaa9765fe714a16123f");

        let tap_tree = builder.finalize(&secp, internal_key).unwrap();

        let output_details = Address::p2tr(&secp, internal_key, tap_tree.merkle_root(), bitcoin::Network::Regtest);
        let address = output_details.to_string();
        let output_script = output_details.script_pubkey().to_hex();
        assert_eq!(address, "bcrt1pkc4whhyja5e0tlk7mp3l5hsy4w0h9q9dynlyuj7azj0fv80l38rqyw4vlk");
        assert_eq!(output_script, "5120b62aebdc92ed32f5feded863fa5e04ab9f7280ad24fe4e4bdd149e961dff89c6");

        let versioned_script = (script.clone(), taproot::LeafVersion::TapScript);
        let control = tap_tree.control_block(&versioned_script).unwrap();
        assert_eq!(control.serialize().to_hex(), "c12761f9195825a851875350e5f248a6ee770e81a5686ccdaa9765fe714a16123f");

        let witness = Witness::from_vec(vec![
            hash_reference_preimage.to_vec(),
            script.serialize(),
            control.serialize()
        ]);

        let previous_output = OutPoint::new(Txid::from_hex("2f4e594fa98ce73a9db4145abfd70514feec01d7af1c90125354520873a07596").unwrap(), 0);
        let tx_input = TxIn {
            previous_output,
            script_sig: Default::default(),
            sequence: 0xffffffff,
            witness
        };
        
        let tx_output = TxOut {
            value: 312495000,
            script_pubkey: output_details.script_pubkey()
        };
        
        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![tx_input],
            output: vec![tx_output]
        };

        let transaction_hex = transaction.serialize().to_hex();
        assert_eq!(transaction_hex, "020000000001019675a0730852545312901cafd701ecfe1405d7bf5a14b49d3ae78ca94f594e2f0000000000ffffffff01984ba01200000000225120b62aebdc92ed32f5feded863fa5e04ab9f7280ad24fe4e4bdd149e961dff89c603046172696b1876a914da3ae579ab6e7dbbf607b3096e32b0f15fb33a338821c12761f9195825a851875350e5f248a6ee770e81a5686ccdaa9765fe714a16123f00000000");
        println!("transaction hex: {}", transaction_hex);
    }
}
