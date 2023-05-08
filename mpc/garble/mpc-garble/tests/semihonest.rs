use mpc_circuits::{circuits::AES128, types::StaticValueType};
use mpc_garble_core::msg::GarbleMessage;
use mpc_ot::mock::mock_ot_pair;
use utils_aio::duplex::DuplexChannel;

use mpc_garble::{
    config::ValueConfig, Evaluator, Generator, GeneratorConfigBuilder, ValueRegistry,
};

#[tokio::test]
async fn test_semi_honest() {
    let (mut gen_channel, mut ev_channel) = DuplexChannel::<GarbleMessage>::new();
    let (ot_send, ot_recv) = mock_ot_pair();

    let gen = Generator::new(
        GeneratorConfigBuilder::default().build().unwrap(),
        [0u8; 32],
    );
    let ev = Evaluator::default();

    let mut value_registry = ValueRegistry::default();

    let key = [69u8; 16];
    let msg = [42u8; 16];

    let key_ref = value_registry
        .add_value("key", <[u8; 16]>::value_type())
        .unwrap();
    let msg_ref = value_registry
        .add_value("msg", <[u8; 16]>::value_type())
        .unwrap();
    let ciphertext_ref = value_registry
        .add_value("ciphertext", <[u8; 16]>::value_type())
        .unwrap();

    let gen_fut = async {
        let value_configs = [
            ValueConfig::new_private::<[u8; 16]>(key_ref.clone(), Some(key))
                .unwrap()
                .flatten(),
            ValueConfig::new_private::<[u8; 16]>(msg_ref.clone(), None)
                .unwrap()
                .flatten(),
        ]
        .concat();

        gen.setup_inputs("test", &value_configs, &mut gen_channel, &ot_send)
            .await
            .unwrap();

        gen.generate(
            AES128.clone(),
            &[key_ref.clone(), msg_ref.clone()],
            &[ciphertext_ref.clone()],
            &mut gen_channel,
            false,
        )
        .await
        .unwrap();
    };

    let ev_fut = async {
        let value_configs = [
            ValueConfig::new_private::<[u8; 16]>(key_ref.clone(), None)
                .unwrap()
                .flatten(),
            ValueConfig::new_private::<[u8; 16]>(msg_ref.clone(), Some(msg))
                .unwrap()
                .flatten(),
        ]
        .concat();

        ev.setup_inputs("test", &value_configs, &mut ev_channel, &ot_recv)
            .await
            .unwrap();

        _ = ev
            .evaluate(
                AES128.clone(),
                &[key_ref.clone(), msg_ref.clone()],
                &[ciphertext_ref.clone()],
                &mut ev_channel,
            )
            .await
            .unwrap();
    };

    tokio::join!(gen_fut, ev_fut);

    let ciphertext_full_encoding = gen.get_encoding(&ciphertext_ref).unwrap();
    let ciphertext_active_encoding = ev.get_encoding(&ciphertext_ref).unwrap();

    let decoding = ciphertext_full_encoding.decoding();
    let ciphertext: [u8; 16] = ciphertext_active_encoding
        .decode(&decoding)
        .unwrap()
        .try_into()
        .unwrap();

    let expected: [u8; 16] = {
        use aes::{Aes128, BlockEncrypt, NewBlockCipher};

        let mut msg = msg.into();

        let cipher = Aes128::new_from_slice(&key).unwrap();
        cipher.encrypt_block(&mut msg);

        msg.into()
    };

    assert_eq!(ciphertext, expected)
}
