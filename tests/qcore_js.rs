// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qcore::{
    account_address, chain_id_from_name, sign_call, sign_payable_call, vm_call_fee, LOCAL_CHAIN_ID,
    SEED_LEN,
};
use qtv_tx::{Body, Call, TESTNET_CHAIN_ID};

fn unsigned_part(tx: &[u8]) -> &[u8] {
    let mut tail = qtv_codec::Encoder::new();
    tail.put_u8(0);
    tail.put_bytes(&[0u8; qtv_crypto::ml_dsa::SIGNATURE_BYTES]);
    &tx[..tx.len() - tail.into_bytes().len()]
}

fn signature_verifies(tx: &[u8], body: &Body, public_key: &[u8], genesis: &[u8; 32]) -> bool {
    let mut rest = qtv_codec::Decoder::new(&tx[unsigned_part(tx).len()..]);
    let (Ok(scheme), Ok(signature)) = (rest.get_u8(), rest.get_bytes()) else {
        return false;
    };
    let wrapper = qtv_tx::Wrapper::new(body.clone(), scheme, signature.to_vec());
    qtv_tx::verify(&wrapper, public_key, genesis)
}

#[allow(deprecated)]
fn reference_sign(
    account: &qtv_account::Account,
    body: &Body,
    genesis: &[u8; 32],
) -> qtv_tx::Wrapper {
    qtv_tx::sign(account, body, genesis)
}

const VECTOR_CHAIN_ID: u64 = 13749533161254861464;

const VECTOR_GENESIS: [u8; 32] = [0x11; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn shared_seed() -> [u8; SEED_LEN] {
    let mut seed = [0u8; SEED_LEN];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = i as u8;
    }
    seed
}

#[test]
fn the_derived_addresses_match_the_qcore_js_vector() {
    let seed = shared_seed();
    assert_eq!(
        account_address(&seed, 7),
        "Q133C9CYVYZNQ7X25H0JJWUDHU8U5G3DN7CQC4J64LFTRSUH66ZNCQWDRA8R"
    );
    assert_eq!(
        account_address(&seed, 8),
        "Q1H2PLGDKK73HPS8PM4EQT5NL7MV8K9ENUMCDQC4V0GKDEJC3FTYAS70UVL8"
    );
}

#[test]
fn the_transfer_body_reproduces_the_qcore_js_vector() {
    let seed = shared_seed();
    let sender = qtv_account::derive(&seed, 7);
    let target = account_address(&seed, 8);
    let body = Body::with_context(
        sender.address(),
        3,
        21_000,
        1_000_000,
        Call::new(target.clone(), vec![0xde, 0xad, 0xbe, 0xef]),
        0,
        LOCAL_CHAIN_ID,
    )
    .calling();
    let frozen = reference_sign(&sender, &body, &[0u8; 32]);
    let body_bytes = "20000000000000008c705c118414c1e32a977ca4ee36fc3f2888b67ec031596abf4ac70e5f5a14f00300000000000000085200000000000040420f000000000000000000000000002000000000000000ba83f436d6f46e181c3bae40ba4ffedb0f62e67cde1a0c558f459b996229593b0400000000000000deadbeef000000000000000098ba0ce08f27d0be0000000000000000000000000000000001";
    assert_eq!(hex(&qtv_codec::to_bytes(&body)), body_bytes);
    assert!(
        hex(&qtv_codec::to_bytes(&frozen)).starts_with(body_bytes),
        "the signed body prefix is the frozen QCore.js transfer body"
    );
    assert_eq!(
        frozen.id(),
        "QTX1Z53T4APRYYYXVGPDTF9THN9RUGLFELZW7J295UQ9PCTTDX3QQZZQAF3WT0"
    );
    let signed = sign_call(
        &seed,
        7,
        &target,
        vec![0xde, 0xad, 0xbe, 0xef],
        3,
        21_000,
        1_000_000,
        LOCAL_CHAIN_ID,
        BOUNDED_VALID_UNTIL,
        BOUNDED_TRANSFER_FEE,
        0,
        &[0u8; 32],
    )
    .unwrap();
    let bounded = reference_sign(&sender, &body.valid_until(BOUNDED_VALID_UNTIL), &[0u8; 32]);
    assert_eq!(bounded.id(), BOUNDED_TRANSFER_TX_ID);
    assert_eq!(hex(&qtv_codec::to_bytes(&bounded)), BOUNDED_TRANSFER_TX_HEX);
    assert_eq!(
        unsigned_part(&signed.tx_bytes),
        unsigned_part(&qtv_codec::to_bytes(&bounded))
    );
    assert!(signature_verifies(
        &signed.tx_bytes,
        bounded.body(),
        sender.public_key(),
        &[0u8; 32]
    ));
}

const BOUNDED_VALID_UNTIL: u64 = 300;

const BOUNDED_TRANSFER_FEE: u128 = 1_000_000;

const BOUNDED_TRANSFER_TX_ID: &str =
    "QTX1V23WH8YGGQ802J0FAWRXQ6M93AHE3XTKLUDL5HY7G6TM3Z2N0Q3SWSZRTQ";

const BOUNDED_TRANSFER_TX_HEX: &str = "20000000000000008c705c118414c1e32a977ca4ee36fc3f2888b67ec031596abf4ac70e5f5a14f00300000000000000085200000000000040420f000000000000000000000000002000000000000000ba83f436d6f46e181c3bae40ba4ffedb0f62e67cde1a0c558f459b996229593b0400000000000000deadbeef000000000000000098ba0ce08f27d0be00000000000000002c010000000000000101ed0c000000000000bfef61de1a2b771118bb634582a2b0e66002825d44d6d0f391d2c9a45cc71bc082039e993d47ccfb81a203aab561f6c6d7c5b54ee29562cba3589db092278dc0ad1d255d806d857f4369c4b4fff10095139de5acb71ba348986ef8a20f53b4da8f70676c3e36142e97e3d386f9c09d95ebce59cd86c497d8ffac841735d2e505e86c12c6cfbb5abdc8838a12a94d3f4fc64e0c2ffc87fcf1637b1e93eff85ffd6f7be7f7c9902bb6e630d28525011c3f053133b513c66984c5b977066c8d90171fde7af644de1d8cef96f4d0ec6ead9f32c415a67ab316b10812ca337e43f66ff25ed7ac5be030e176b58d41b90d1acaea7be802d70ad45baafb8cd11dd0ae72c97e2d3e81207d77975bc45aa5aeb24807941581a2e07516c8fbba52f8ed3846ea37ad94234fd02e7abfa7694a0676874bb3e8d39dc2f5a203e09ffd46b475fa66c19438b907c3b331799b37882f031b03133fe9e1ccd0a5d55d90abe9ea3733b284f04c3694f7fb53e1b9766f67bf7838c928cfbf1d7ab80edb43b84c1b1cca4183275e8b00aca4d0e45e4e878c405b76c9595cb6e879761a9f209aa7f9f3f67be7b2d8ad5106ae4d80e2182400acf69f0505383f460f34b5ab7eab6b365e55a08999b7d4a1fbf31a87588baa91d137ed4659a9b8ab26d209b2d7c6ca01eb06e359181629b7f63e2cd5f76f1ce3ebc6dd58de9ea15b17c66c5209c22cc8bc414a1e3f8f75f98dd22c4be9ebd3f22b001210785de23b8d8d9f2fd5ed4f682925617d28af3543cca7c9acc956bb6ee184664b027f2a9b7b1f0b20d198ab88b2a9af76d8444f62da764ab13f4a820d9e6bc12f84453d74046c67da89099723ae8b9801ab3786f040746281d0ef99c2ea38377f701eb1878dba4872059950afd67c8c3b50fe9f87804242addbd13edee312a14eddc88b84e469e446d2d26bc8179feab0bacb672c21bbf797aaf5141a71362cacd9148857e83694e63d8c65c0e1d55f360490b3b6a5277befcb856911e628e20a3d2a3401ce5d8c86e56972d3ca041a79ee6d77ec377f1dd4f7959e5ea1879dbb7c3030682018e60ce18054fcc70cd95dc96d89d99046d78d029d84882a538d4fff35c4828c25aa64b44afaf85d162eec1a97cf75ed78151588068e8413d876229b7e11d323fd720930bfb487d429c79f81bb81aefa53096f16c3a4ed52fb1ee9ee11340585d5f073a21216e90a1007a1cfef4ecf0edaf41847219eabd2dc0690e0b2dc85a245d29a6a2be87c97fc11dad2d9870cb18ceb9d0cce26d1a6c4402435518b7379d810c82b57653dcd11fe9ff82c3337d121889fcd59b546120de11643dac21344e768c27891b6d00a4936510ce4096cc17213d342c261c6a88137e140b3e299778fea31cc36072145d8448e703daac4779eefb74b1ab5152fc99cc40a0b7b3e4f4630fd2dd3468e1ac8af82b137453d62ed4623d33cc495ed45abfab8f3547ce7418baa8ebd33a49c7fe81bd1b8c69a00bd1944fc4f4627b8792bbd22a5e74deef141c16d424b1a1e4130fdf44ee8da9da02be184e1a85823938be50392d94dd2e4b5cd7c76e781d4a988e67d78740fca617e98602e393c6deda1f91fa37582cd1df6229933174c5de0c66e0b4998f03b3a562751d5a502b17140ed6829d98ddf5857722d667e7390efeedec4723c9ee8e7db880d497d5ef9cd2e5d34add46ebf2311095bf054af81f47e92149df5001af517045c03a3ad443cd046a77c7aac2e6a2bbcbd73d185f37f9614277356ae68667652a57ab71971173b9f8fdc2983608522cf90aac65efef5e7c73cef9702c3f771b58386f5607ce873ff7f997ab6a3c476f0f35c0dc94785e29aa54c03280444d64a411e48cec8325a245c4bb1db92d4c7ad920e9774f182b20be3f596350a55ced519456e5e8990efe32c13981a5a5889addb4b1072f22389b669aff6025a4ef40c96fb1e4b077d30ba7e404bc7b781f6297ec6825b7a82c54941c77181c533f6f1a37606365e1a7f67f2836cf4e9f641254bc1141238a5c8a2f87e45be85c849c0ff4e384b894ea4678a42b6c6f29336a16be434ca50d9e12b3d5f51d45b7cc355f7a42a64199515d83a27af428519a21397120d81b0594c086d870309a18076c794dcd8d44c13765f321794d29ceb744bd340caf4eacdc90a2b6f1c3ac31877fa5267eb935c7b87461c0946b6fbde228e48e1169de49e5c940535dbc5a42b806192956a331f00ee965f076fd83bba609d784398f9686b6db10a4ac2e0fff993a966be947cab7eb657d1d0288ab7434ea84fd2dc0b7debcf80bf67c33133fc0686b3121fee3cc708c9c304d71ddda63452b29ea4e2c08211b6528cb9c799264c0969630ae67e30fd6d354bf8a5f0355399d74c0792b13611f4082376e9b48db720e11a1d418bcddd0e0a74c4491cd939b12ca001b24eb4bda6929ac9e6486c645b2137d271d69fa2169f0490d4451bc65e8a085de7453cd8c323cca8f6ac9374400ef3a6e50c2ec6fa64d5ae5273d16324da7d804212ff38e73383d60ada518f135ffa78690ceb42e7c7e1cffbc593b684a543e28989f7ce5ed96f7206752240fffc5463ce7b72eb306657178f54b54cf113afa866fe3c5e97958e555d205faf93cd4efed9583c92b0eed384fe76249591564984f0ea41b62e5bc956a2305a7c99ab392d39e41e98e7e9f2ae5fd8d003bb52298bf9be42aee484d5748b0ff7ac6adb3cfb85a72ecdb0422ab849f5fc441089a8ff069b0744c312551346638674c3ff8d0f31e0cdb5a20748776cc1054db0f8b74fcee91044d10f1d0fbbd30f802f8ca5959a612f37afcc76f2d9eb7cad7a45f4517e1aa9a8c11c3b156acf51e0484dce147e3a92e3b2057fa7f08f2c5755cda2a6df8c451c134fc3e6ed9ac92f2ba3a53bbb4098547f542e970f42d70673382012b5b0d32c2c625d6f29d1d9c10fedf9358ea90604f8064389dda5eae67888782d28b27c741ee01ea80080d732f635e65408d87def36751f02b5971e0c8be800783a343d450ca7ea4c6b6fff0c54c7355b84c0c9b1ed0f2f675d21ee3812b946e8af41f388a9431aa23fb3bb0fb5343a2c863c6959b29a3c817a5ca74592af8f249ad0e1c90f02069d4f2558ee702c6ca91f72476b1b535a80d8d0e6305cddeef0f0a4193c559886b0e41e7d1a78e98be15d9bea17896cf83c58466299ccdae1ff9b0a7fca2166e3be7acb6713cf227174ab441bf83d303445be96010ea00542b7558cd46913812126d6d1d8ea1a958facd251bc02d652e57eab803c5507bac29b3a11136b1d29ca81410187c6e8d01d8d56d561976e60a9ee0e763de3b4f116769764e83a80248bdbcf9a9c98eb4cc5262cd9876588c355f6b466263428c0b73a25f51c323e19f10158e2cf5fbfc07dc1370555fceef8bc4120a6d64fd33c30f6300473d14a4f1c3a7052cec97597c862bdc1835417664fe0fa679d4b5bbc289962258fa4fd90abcce47d9e86f1d767874a427952bf32e54f16ca2da70cf6b690b87175253e871801f492e04b04b420fe00635aea28ec3bf1e9cd4b602056fdbac1ab06cd21aee78eecc0c4125bb748d82823105ecc29d7f5841f9256b26a8aa1cf36ce8ae3716436100e66b9ee6385c3ef5379fdcfdbc6cd0ff9c826927f49ad877386a1b69f075ff79c6619c0319f6dd75643860405be14b822e293170f2d1a146d4041e14bd29383e55e9b92f2e0175f5c8b72919e7bd9fcd09baccfd1b7bdc91757b46f176b87dc5a213efc33c0ac0fdc742a244d63371d7216ed4eeb0250f562b0f7b496902d726da86c96325a4fc7c16dd6d078225f9b9506afe7ccf8164b8ea56d9da830bc48b6a333aada2ab99e7be6f2b143fdc9afd5635e9afa875db73d914418731f35a5d2d841f9ef196cc0f35bfbec77ba6f92ac3788f159aa7f4e2b21e8c428a6f49f160cba01b147ef58b478a13f79f949990c6b41ef270e34e276fdadd4273d527bf87ec8332ef0daee57e31f335e42506b5c08bd4267e8fd1ca5a7c4526b5e3f24ac0932578768f07cd746cb0f7d3e1f64df50fe40acd2ef07cc3de31c201b78fde570132aaea9c886f230cfb3a24387f0a60e3d7d44e29a6765189d3510e648429058fe5da4fb68b248ff1b66d50760ba5d83bdd8aa36078bc5542ab59a2d94df99346e0b6526d2e397ed5f5d6c05ac1f24253bd9504cc5e44e5d785ccf8fb48260b89b69c2010df82c942d81450fdf21383f0b8270b00489f2d5e2dda8a0988d970b5971fb0fbaac25ab4c36c3a863938bfd183380241ef0c4384e832f1c1c92ff46352b0efbc3b7cc231b139dd6a8331781d9f25a86662e4a5d30953b5fd229c5b991ec4e2d972761c56c9b9b5680a660352cae5cc670fa0c2eb76ac3c6ed7d8ea71efa4aa78ef91dbde9e55fddf4150002209d9222198e900ea8aa59a9240c64d1e55a6d72c4d2575e3139d3931c103ef8d714b5958fbefee26463f4df74a8ed863e1f8ea7f6b02b53b237b2d7b22269f9346254cf5b37952ee209f2ebadb84767a077e47a1579d5b9f1635bbbfbbf260d940d7a4fb673e48c6de388ef4d1223264c1a5df0df60b8cc084d75b1b3e2e9608588b0b2b6b9c9d4f712357697c82b84e0090c465663668392b0bdccf80525304750587cbabbdbf500000000000000071116192530";

const BOUNDED_PAYABLE_TX_ID: &str =
    "QTX1YSNUJFD532J68Y8KUAZ495KP2MACDCLT809N6HSYQ7NM2ZQWSC0SRCPSM8";

const BOUNDED_PAYABLE_TX_HEX: &str = "20000000000000008c705c118414c1e32a977ca4ee36fc3f2888b67ec031596abf4ac70e5f5a14f00300000000000000085200000000000040420f000000000000000000000000002000000000000000ba83f436d6f46e181c3bae40ba4ffedb0f62e67cde1a0c558f459b996229593b0400000000000000deadbeef90d003000000000098ba0ce08f27d0be00000000000000002c010000000000000101ed0c000000000000a3533e107f0fe58861552281463028bafa4f6ec2d4bc6d66b9a903bd05c69b6a01aaf9df276d7c99df099a094f2290fb39bfdc55ef008ea89587b295895f8a742c365e228e308e7c48ef84416c784101de6958290dd04d119d4882840204a973ce9d51f965e58ac6591db4e249d337c20b5fca0eea09bdffa0a8629b3fd5790a39ec3ccf1b5e266a639440dcb27e1ade1818374e7cbb44ff3d2b68e01ec5364491dce786c0ce62894ff1afc2c2f9459172731c6a59cca270a40637af0d28b776288c1145db678757492d9b08584f9daccaefd8bbadf267863069436e82aaf4caf822e2f423956b4ce70187aae62209411cae0b29b3f8f300972012a51b611c24b9aeac6f5c1fb2cc783dcbe2f67145a75abeefff2e394232f559156eb20eb0d6679e68bbd3d9341c47588f727118804b93039720f068be68a904fe88efcf8c09e6e0ffc4d6d621e8615b3362d0718b1c23555a5127dc5df6b28894b46d01d38d2c0cea43af04a5384c5e1df12d2af01db66878356e82196b03819babea7e538bbbba8216cb3ecfff3ab85ee5e6ff1883cc8760de17b92c2fffe284a61f61b088ed7956f6b05ee45e43f7b91574abccf85899b3a1273d78c1f6a9796be2858473fafe0a308840018ec7b899a1504eb94640fd6ec9b5716f0830ed08fa04a46627c6404df560634881b4bed1a0a716ed8e65a9882c6fb58d1e1e55e5db6cbf2650f7de6a3c9d48e296772dc4eb77da57b21d790741422d808b87a9767c6fced69451ebe5a00e2f08f4ebe3ad7425e22586ef46462e1683e12e0778f926d65f0ba650f9fe843897c8b4fd6d3016dfbe8252eb608ceace96adc0fa1312cf9cd677685fd523fea2ff49233a07930af95047759677a2bfff0e8afdd3d0ecebec2dff7e7f744351f0cc86f56992fc1863788e484bbe154e01e76d93016a3119319d03d898912fd48a65867f1c90a89604ca2777a0dac9929ba724762abaca38465e680e0ad2fa4c5775d0a42505ab409a8c215b8aedae2c4919c8ee2ae8c1e4180162c328acadc1cd25d8a9f2e96179778c320f50e0b8c9fc5c601b81fb7b63a16562e6a05e24d9850ff04d0b1c62e2d6e571d37095ba145f5fe87796f6d82106241ed95cc0836f57746c0e3a163d1f2734739a46cefd0db4612561aa6ad8f08189a9c64026947578d6606f6c4db31be32c6d3d6285f733cee22cfbc52b4795b71bf3275264e93bf51016758a57c6be4c93bb2597d6b6c2cd6d41588b52397f4194cca77abe3d0f86a093477d39781bb33cad0c2646bc8d02d22e86b2521ab862181a7949b22acd92a686ec59adbc18d8dce96e5cbc447e1a5f8d4cdae32ec7243ebdaa9445de92ff3248fd7823dea073d1169a3d97f59356341ee5cc1851c60aa2276fbead2622397143bd73c46163d05ba75859edb8fcc83a996f0731f3b734ef74754f9ea393021e20002c2fcfca3258ec9142e90edaf5772a6bed961f2a5616edce748f3ef4d638b0e7e3bedb8fef9127791dff1b7e2c99b234e8e08b51fb461da5c06a41e0160c5dad717f237bd7063afe86f69124331b2502e76f848fb61a7515e29ee708e89864d7e4f5608ab88571c370a6e5210fed1513edfa9091b705f28cba6fd9c285b60112e786d600276196293d608072ab35ce2d6cca58db3f15e62a801f4f99ced1a87d14174ab31ddee58af6086efadd2f785b7e4613e53fa00d8105dec6d910d2d0c6fb8e2e56873d09f445b3b6f7339d229f24c0af827a4930489a3de4f5d7a528f226d529c6a4cf2daf143dbb33905faaed985c67ed51cd9d01ef9063a74ee35b5ff96458af5078f02f4374fe6ee2e1d1f5fb99cf80cc97f4932a4fbdaca08a82b7c3868d69269e1fd36786d40a36e825aa78429d466ca59bba4c62de7e138b56b917b4ddb1b15c7eabcb905594f352edaa929a3f75b148e465be29c47b6cf74743e2b42dc4ee8ce19d54b003564e0924e1649b2fc1d0fdffa28972fd4bb934778f151710eaf635892dbe4dfa8f78d5822074e0925a79ebcc37b16b3841025c27ca3dfd2420a11e85f069e1c9ef2bdfdb9ba2c7910610c26a423cfedf33ebf8da15df622f321c33d32ea07f2669705a1da641364d6c14a7b93ebb0cdd4aa4d1a0284d72b43d312f60195fde367e075802f52d9e514ec3a88263db4f10c9a1510eed68a1db56e6df127caf5b8d35022e9319629167cdd6871a6a0d93652a9e67504e93b988514fe1ecef6752506592e1b76e9d07c325b136732593f413dd48115d3d5dd9877c69e97a4098ccb9a96b928accfe33eff7d9088c0865bfc000bd383041b2a1b0826f87adeae66ae136c3389aced6a74712590b536d03f316bc528fe02665d6d5e24323b7c283947116fd407d89c0d8858b4fc5b686872093d7458379327e172e83465151605a09f380078db7778603ed60eee618acff2bf10c82bea1b6367d8498ec3088fbbba6258afb40dc99461f4e390e15b2294982c4fb995229b03a309f83a91fc4f1bd15bc31682902913e7ab1b94a81f6883caea70c82d1d483cd699763bf85fbbdebf1acbda794534fb6df929137c5a1da1ce4991fb1d22996a8fcd45acc8b6126271eb6cece51b906f68ab41c491c4d5389284ef27a5ad0f366e02135515e58e6bc03f76392e30e7aac5605c38c78bd75c34d00546d189b57bdf56629486e5640ffb96f1f938e92c4b9a7dc6632d99482db1d979b49ad079297e9ba62011662a00b4a854e02d8d1c36ac342ed2570342ff4f33c6597e4589585a0c3d233a6462683756a970c14fe0ad5242de71f3e44f3fc1f63f246c8a90e36ab1514d5ac488260a2175b220a36ecbfe9adfa30b20c23a0ae1b0e1da5043b6e99742e85b4a58fd39a5014e4167492796977b951019da1a20236340fcb112739c3768a2a21dc035c614c4874a16956abf3868d85f87ee1faabd34b2af4ddc4ec122fbb7db09b92a1a0bb76f8c337219637259e689f9a2ac46cf0344e423707dd76f3abf48c0f793242965af42854e1023d3b83f935f39912198e7d9f085943f3ca696fc54a98d2cdb5ff409c80e36d7cee92a33ed9e123eecdd0cba33569824ac43a833a6ce67e764c934d3e43dbfaf386c1e444771eddebe5859ab2cc74aae912907c04b017230347c0f87c81edf0135153b4a8addb4dc01feda8eb82e9fc0fa17758cc9c118524d5df4e27c6a2878a46d517e5c7cace1c6a079cfb8a38f90ecd259000693cc85694aa2e4fddd0d683442c14402fb7c05501bbfe38710d0e07573a3fe75786ee53f5ebced559ce598789ed818e89274d888d46bb1aa1a8a5c467b3dba7b9aacc0ea8ceda8f7800aa53afd808e7f045e4079fe8d9b4cceb0518762a630b6c37c3377f006b4af519dfdf56f04e542bd3e085bb0ccb51c5bdc5c1f3bbd3a7b21fffeed37eb89ae0980907e9f84e2a1db559917b6e6c813e281a6229ec95ebc11da782ab4431fa1b10678c1acf759f44f484eacfcaca07797bdef9090356a8f43c0d0a670a7599265365f884b8aa755f94c59dfb577ea58be3621923af95d4040da134b208567f45d6a8cb7860e24b26f792daaab79f82fe5d4957ef2307cf1593b62a9b1f5065dae9b412d4cec7b6a89fbfff39829dd1caa4ccbf8cb20ba0606ab18b23fade8aeb74291dfbf7fe69679b0ee8112314dc75c420d4aedda06aba7b9be4736dfb204ec53c91b47afcfe0d6d6314d5d14d103e6a9b62588bd493758429e7209f2e27ab4965363d10998bd6e7d350b3772046699f33dc463a2700a6a4617e33924ee2ffbb6348385517d2ca3e8190c445455e2809d25fd5af4bf159091a75e1c855f594a49b6460980760052fbca1701aa7d0a7ba8041ea87c012c4b22b9db7d100bad1f6488f0ee96cd961a924d1ea04dc1b809385b3a7a473bb9cd61eec928dbefd8863df6d00a48b6d002f00e2f70281e507c06fadd218d7bba05525c1463112a8deb64bbda1991c0080a4aa271cf7b6682582bb511fc23843b3245780332ab80f41a9c31ddd7304be38c7e51bcf2b8f4944c7487ba29c5ea43208f68f006b4c79236d96ac6e6c6f1fc3bd986a9aa326d9f34224acaf5f5a78712510b1ba08fcf3561f48b9bbc55476293a71cd0bab977ff31e8ffbfc71f98d0b8bcda6542b0eb6a95909487f7481fce416890c5bcf1e154d8af9b4edd4e7bc19abe999bd816ffb90395e348b21c0ef7b7a5d5af88c10e4bcc36e84e0844805080b931bd2938af9c8d310da324378816292791b680f60e1298529e570dd925bf40dd6cb0d26a9475841ab8d759ec67eee9341bfe7118de4bb2b8ca19a4ca27ad64a89fc6c98a8067e01c4f744848720c808b257cac721c44cbf55a099532da04b4a83efdcd0cb95d983c64c90e5a5e422f5aa226d50f037e53323378ecf2b0857f76fc26317bafb3fa48b840cae76c294c98f751a1bee1c88fd354e87d1664feee6c74db847a3607c495511f8708ab6f4b506a0cf44bc3bf8df0c9789273bbebba98251142feeaffa6499acbe548c0c8796af6e556a3b98ed2bcb5ecc43066e209e9c09aff888e38cf4e78c612190d28360a97539c4af341da1b78a7dcb7ea2faee714d62d1f7f8235c89b8ec123438397c88d3ebec16999ca9aec6d0d4dcf5506eb4a7d8000000000000000000000000000000000000000000050a131d2022";

#[test]
fn the_bounded_payable_transaction_reproduces_the_qcore_js_vector() {
    let seed = shared_seed();
    let sender = qtv_account::derive(&seed, 7);
    let target = account_address(&seed, 8);
    let body = Body::with_context(
        sender.address(),
        3,
        21_000,
        1_000_000,
        Call::new(target.clone(), vec![0xde, 0xad, 0xbe, 0xef]),
        250_000,
        VECTOR_CHAIN_ID,
    )
    .calling()
    .valid_until(BOUNDED_VALID_UNTIL);
    let bounded = reference_sign(&sender, &body, &VECTOR_GENESIS);
    let signed = sign_payable_call(
        &seed,
        7,
        &target,
        vec![0xde, 0xad, 0xbe, 0xef],
        250_000,
        3,
        21_000,
        1_000_000,
        VECTOR_CHAIN_ID,
        BOUNDED_VALID_UNTIL,
        BOUNDED_TRANSFER_FEE,
        0,
        &VECTOR_GENESIS,
    )
    .unwrap();
    assert_eq!(bounded.id(), BOUNDED_PAYABLE_TX_ID);
    assert_eq!(hex(&qtv_codec::to_bytes(&bounded)), BOUNDED_PAYABLE_TX_HEX);
    assert_eq!(
        unsigned_part(&signed.tx_bytes),
        unsigned_part(&qtv_codec::to_bytes(&bounded))
    );
    assert!(signature_verifies(
        &signed.tx_bytes,
        bounded.body(),
        sender.public_key(),
        &VECTOR_GENESIS
    ));
}

#[test]
fn the_payable_transaction_reproduces_the_qcore_js_vector() {
    let seed = shared_seed();
    let sender = qtv_account::derive(&seed, 7);
    let target = account_address(&seed, 8);
    let call = Call::new(target, vec![0xde, 0xad, 0xbe, 0xef]);
    let body = Body::with_context(
        sender.address(),
        3,
        21_000,
        1_000_000,
        call,
        250_000,
        VECTOR_CHAIN_ID,
    )
    .calling();
    let wrapper = reference_sign(&sender, &body, &VECTOR_GENESIS);
    assert!(qtv_tx::verify(
        &wrapper,
        sender.public_key(),
        &VECTOR_GENESIS
    ));
    assert_eq!(
        wrapper.id(),
        "QTX17VJ4593S82NZS85240RVPH6Z9GHTY57DMTRZYM3QGGWU564W6G9SK8G92J"
    );
}

#[test]
fn the_target_case_never_moves_the_signed_bytes() {
    let seed = shared_seed();
    let upper = account_address(&seed, 8);
    let lower = upper.to_ascii_lowercase();
    assert_ne!(upper, lower);
    let signed_upper = sign_call(
        &seed,
        7,
        &upper,
        vec![1, 2],
        3,
        21_000,
        vm_call_fee(500, 21_000),
        LOCAL_CHAIN_ID,
        300,
        500,
        0,
        &[0u8; 32],
    )
    .unwrap();
    let signed_lower = sign_call(
        &seed,
        7,
        &lower,
        vec![1, 2],
        3,
        21_000,
        vm_call_fee(500, 21_000),
        LOCAL_CHAIN_ID,
        300,
        500,
        0,
        &[0u8; 32],
    )
    .unwrap();
    assert_eq!(
        unsigned_part(&signed_upper.tx_bytes),
        unsigned_part(&signed_lower.tx_bytes)
    );
}

#[test]
fn the_display_string_maps_to_the_signed_chain_id() {
    assert_eq!(chain_id_from_name(qcore::LOCAL_CHAIN_NAME), LOCAL_CHAIN_ID);
    assert_eq!(
        chain_id_from_name(qcore::TESTNET_CHAIN_NAME),
        qcore::testnet_chain_id()
    );
    assert_eq!(
        chain_id_from_name(qtv_tx::TESTNET_CHAIN_NAME),
        TESTNET_CHAIN_ID
    );
    assert_eq!(
        chain_id_from_name(qcore::MAINNET_CHAIN_NAME),
        qcore::MAINNET_CHAIN_ID
    );
    assert_eq!(
        chain_id_from_name("Q-test-net-01"),
        6_995_079_887_857_407_393
    );
}
