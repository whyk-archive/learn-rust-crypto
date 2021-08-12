extern crate aes_gcm_siv;

use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce}; // Or `Aes128GcmSiv`

fn crypto() -> String {
    let key = Key::from_slice(b"an example very very secret key.");
    let cipher = Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(nonce, b"plaintext message".as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    println!("{:?}", ciphertext);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

    String::from_utf8(plaintext.to_vec()).unwrap()
}

fn main() {
    let plaintext = crypto();

    println!("{}", plaintext);
    assert_eq!(&plaintext, "plaintext message");
}
