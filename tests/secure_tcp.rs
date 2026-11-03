use hbb_common::{
    bytes::{Bytes, BytesMut},
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::Encrypt,
    tokio,
};

fn create_client_kx(their_pk_b: [u8; 32]) -> (Bytes, Bytes, secretbox::Key) {
    let their_pk_b = box_::PublicKey(their_pk_b);
    let (our_pk_b, out_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed_key = box_::seal(&key.0, &nonce, &their_pk_b, &out_sk_b);
    (Vec::from(our_pk_b.0).into(), sealed_key.into(), key)
}

#[tokio::test]
async fn test_key_exchange_handshake_crypto() {
    // 1. Server generates server ed25519 signing keypair
    let (server_pk, server_sk) = sign::gen_keypair();

    // 2. Server generates ephemeral x25519 keypair
    let (mut eph_pk, eph_sk) = box_::gen_keypair();
    eph_pk.0[31] &= 0x7f;
    let signed_key = sign::sign(&eph_pk.0, &server_sk);

    // 3. Client receives server's signed key and verifies using server_pk
    let verified_eph_pk_bytes = sign::verify(&signed_key, &server_pk).expect("signature verify");
    assert_eq!(verified_eph_pk_bytes.len(), 32);
    let mut verified_eph_pk = [0u8; 32];
    verified_eph_pk.copy_from_slice(&verified_eph_pk_bytes);
    assert_eq!(verified_eph_pk, eph_pk.0);

    // 4. Client generates client ephemeral key and session symmetric key
    let (client_asym, client_sym, client_key) = create_client_kx(verified_eph_pk);

    // 5. Server decodes client's sealed symmetric key using eph_sk
    let server_key = Encrypt::decode(&client_sym, &client_asym, &eph_sk).expect("decode shared key");
    assert_eq!(client_key.0, server_key.0);

    // 6. Verify symmetric encryption roundtrip
    let mut client_enc = Encrypt::new(client_key);
    let mut server_enc = Encrypt::new(server_key);

    let test_data = b"hello secure rendezvous message";
    let encrypted_by_client = client_enc.enc(test_data);
    let mut to_decrypt = BytesMut::from(&encrypted_by_client[..]);
    server_enc.dec(&mut to_decrypt).expect("server decrypt");
    assert_eq!(&to_decrypt[..], test_data);
}
