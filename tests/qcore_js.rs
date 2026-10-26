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

const VECTOR_CHAIN_ID: u64 = 6995079887857407393;

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
    "QTX1EKQNTDGKLEGENUGJVDH6LTRPQGWN43LJLKSZVNUV2G3HDDVFJA7S8C0Q5J";

const BOUNDED_PAYABLE_TX_HEX: &str = "20000000000000008c705c118414c1e32a977ca4ee36fc3f2888b67ec031596abf4ac70e5f5a14f00300000000000000085200000000000040420f000000000000000000000000002000000000000000ba83f436d6f46e181c3bae40ba4ffedb0f62e67cde1a0c558f459b996229593b0400000000000000deadbeef90d0030000000000a15538b31884136100000000000000002c010000000000000101ed0c000000000000e945de0b8c34a10b67d6056dc58a34736790f48980f098abd01b178a7aedfcc8429dc762551c48ab4582a484a61a19c8f9a6a6f0bf5fd46a217548e78f4d8b73130022be2127bd3ccccb53c7a06c77409606b292d52fe8341534c19e3dd256ddf8ac65a5253820e42b3c57b39c15781ac39db9e97726e335beedb4bdec5cee3d87b97a3575c8f0108c0bbc26c224de8afeb3ec50ba843b7961ac696c0c784aa8dd238db249b26d4d35bfc9e36dbc5b65170c00a7ebb141dd11d7265ad245037e2059368450c711b1f2ef037345ef9e523943ccccfd892a1467192bff56883411e22c1f0fc09a0f37d6dbf91f3a0d7062e845a66201f8006d38693763e06a4e202fad8e36f4cab176e48f57ee320e6043ae44bb2a4a7e0f9fd9022d09b9782e327f366e8e306f4fea89f00f9224553e24d103c4004267a6175a389c4f3c6f0baafc54dc4124bcf42fb2b61813b1eadae8c2c122be2033aeab3e80b8ba48b66a12cba932581b76279552e9c471db4ab0470b17197b6c9b74e69d60ebc1d859c3da1893bee67e0f89c85769d69143f2d9b8fea01f9208c012f531f60143f7682dd5cc8d1d59911532cc21b3974de2c685afcea636bdc69975b4eecd0dc1318bb1fa80a9aa4a3d6878fc7a57491fe6f29f82685ce6b16bb56b171f045da611aedbb28be0674eeb12fb49d7a51f2f32ed0bbafa74df23ef890c69ff93854d61f7da489b9d635d53b4277221a9afa2bc938e0be9f4e1abadf9abd25bc7740bca1ec39fb37e7961414b4638e3b745a3ca3c0d94deef7e3508c60bd64233b85ea3b80cf13e2414b282ff770a832e509edad2407e2a3fd4fed2dbeeced8a7cea87a9382c73cd3839d06cc9a61857f1a3ccf3e3bdcbb3d9c041efe788522b261d781b83ed8e375fe9300c8f71ccb29bfbba8856951e3dc38cee910c3cfd6a0366183d3d50c7329f34024c593087bff14c0324949c35c53ac1c7c4d18d655b91828f219f5c3f0f3508758b3f184d7af37c15fb262b0abad3ce8f277635e9c2ac58c9131db2b47920aa80194b410651b7c1743624b36ea76d33e7640a67ec30250922b7ee5856c50699a07df1f5abdd767cceb663403b2e336f922e582b07f57081af4f5ab60341407d793656511012d18d9d4e3f607539ae511ed7ce16153f525f01189f17ef62b3ecb034a348257d753ad9c2e9592df6bab26b1e4a05927eb740a2a028ac3e2bd1fdf46def43117b7bfd0f6fc9e22389571b5011a88f19b8eb57694fc7e99d5444e776cc37818dd841433b786b266ea00884b51de937db896cdf9359edd0e848a4e64fc858aae1fdf286b624a17bc21bede0b06076f48ea0e2463c98bbdeaabca2b41f90c4de7b5ec1409243fa2138391ee66d74e5a17faf8dd2d1f3bf556f8b6e5f7b24e33a1bd72143c570c10c4144d7a4ccb90042c9b396cc0bdf829f9fcbfbbe7bcd326954654a2995f58d6bb9185216bba52e014d4ae67b9db53b737f82eac3860628372df7ae0667220fd73c5dd8582f7920a3e42ac962fa7360a8d76f9f198809d45c88868a4942cb7b705bf1fc923e01b8f885ba9c8fb46869e844becaf3e6202342ba1b8a62916c739c9002f601191da94928cf4d91d9d5037e2c16cb53f338a79cd7dbd28a4da35340021f4d27a6c2e6a59c2fd7737eb3c8ea9e18db1dfb5a315613518a2a3ab168655e44154b4cb98f2323f7416bf90fca2833527809dd3d3485e5ff1e585713c979bbba62980defd29d105e1671581fd40c02de08e1dcf54d1b79dfdb0be1ae602be98083435437aa38c1f4b50d0879a91fc45a9c5446856704c8257128422d456a5dd35e3e1991905845df3d90318ff9adfe499ebdea3e082943896d63301531618295923592bb8201fa6d76a6ecb379e918d1ba3d5d52bbb1dd588f80fcdb13a5830fdd8231ad47da936fb4dad87862c38bd8224394dd0bdd0f97ebc8699ce9cee5f8fd44224895bd8edbb383ee8a6dce35c013c9d6a9d8e141782a221dd73c304c3ba7ee0ad74fc7638bfbbe9deafd916f3c064829bf1200a2e85ca237493ae608c31368fd99570610f41fb2f917d0f17ac113aa2a9e1634b2a44da931c88203fe593b003e3756a4e5e91f66751f132f5e95bcaa66845dcb819bde084f1a35939b9d92a26a23633d8a5445b895d5372490d7ed331624c4e0bd385aeb43704a913a62f4c42c96e01ca4e3482dba0a9bf4ecbf31ec41d06b6d71e7712c3f42b8e3b5309944a46e91cbc8743a623fd9e4f9043679be2ff8c307603e9026d7fb8385e7603d5218d082af1f00356e50a4b33eae3fbb0155877ef65c9d4b8bfdd2d14dda3bc32ffbc9aab04f7f8cf111646e0969f6150a73fb6b73d4b61adeb7d446b499301818cd258bda3ddb95f64dd042beeba84b5819ffc28fd931f08979c9c777b9e9bad0007ce6bc22ad15886e85efa7341d30b21126bc9904abcb6d004d80f93973e06f0e99728f13ccfe085e149ffbdbd47f79c321fa9bf344af8ba7e356fbb85b4900e933deab37f9d34902cf87268c22f75eaab2be7ac0ce5d1aea028a9d49f06015d146d372b3b64c2b4860e3b1138b1ffbce6417a9d07f02ce88a736e7be7f5857f39ebb3e2c238597f1f0e1aadd5ef6a12eeb45282826779812519dd86abfa6b1d67c13623b616eb6f0507d56aad0bd612c62748e7e06936bf20929e6f7f225bf95dc61d24ec2959ccde26d693d7480239eea70409da7c5bd163a85d7a8407c102c56caf4b7a97fda2874521609246fec5385d44520359ed7c5009f46cf977e49613bb663e4809a7ffa4871bbc88ff421b00a59dae6b5be122d61280485aad6bc581510c47b463c584293506ddcb60f88cb087e93c93688c0ca42300bfddd78e4b361f87ba0ede0e1a2b3e2da0fde1ad6036778ae2c77749cec7d9a647906a31f3bfda1f629c691875361d53be22be24e01896a467fc68324315f4d6a343e2b23cb090a24c2cd1a22babf648f64be71751ce97ba7c1c287fe61c7c49f1baadb9ad75103da4e401d4925e7fbbd79c0025e82f3a2cca33c3f8b9adf6d9e3193b18a2818f707e2c81cab42233a30c7937d18fee74805dbf426e10e034f372fb4fa283140f32306d89b76ee3790586bd323fb573912b994c203900fd7ea3e522c04000d2248b47f8bcd637c1a9e4ddc8c4026c5ede84c75a94809e31d9a917d9bc980ffe66cff145dff50d54cdac0e3165fc9b5753f8f6350074f5182045e222bcaac42275c9910011f534f65d4446ad096f4eddab16e34e20336e1286299e003fb6c30e7de2eadd85a26fa750a1c05b2f31fd4520d9b201669d138f07b6717425737398e177070fe05d038d4d2073dc57583cd080523dddf4a3d8bf40c65f5cf5f8f92dfb42eb251be748ee66244f43dedb73d8f1bf77523d96878cd91a9cff5133604a3ec551bb66826716309482d7d4ed5c1fa16dfae6a73b18173f5880fed8090ff27e4c1e5e172a1fd2a15ec6743c0a3442d2394d2b922cf9c431c318eff6f5b3888b32b1ac0530b1994752315b40d38e77986c51c785f84206fe745d6d484107e4680ae3e513af7edb0e5629dc62ca494a240ed1e1849857b080fae0d8b2ccf60d1403f67e8abd78a1969e8c34b5bf9d7da42e5dd354096060dcfb7d71c0ed4f26b70e1b4c1418cc3296e68349ffe77a4e9f4ac88a73685322904bafccc7b0bc3f3a8b480fb5e2e5c39f3dbf63eb3928944327d9ba68e2e92b19001cb896b28211af376934fd3818f41440907861bf5e2196ee2bb0194fa5cb5a5c6588edd50ddd602b221ad2d96feb8569c378ff9bf8a7a3041fba9504760a5da50318cda5adff62327e089e63d7be122f8fe7d6daec4b6968974eb5243dedbc229fea0ea3f93d461058dcc6ece2d16a2b0663dde40cc8fa1a3370a1915a29371a780d02b96cb8dd708a6dbf1ad32ef4587055d49e660f36ba39878ff200933cd4fe752d37249d47d29c8bb41bf56e07a78c141c9dd0e7ea62a267fde9fa32bdf4ee716e1f0ed9fcbbe5132f603255225d8361f58124889c7b009e167196e68bda1bbcee56cc56838d5474386605b1ac32d29e7d9121b1b1bc3d815c3114af43b783e6bcae498f1f0fbaf45480ef2c628b8b47b62527108aab7110636fe488c676adef3f56769f844b2be3f92dc42273476b848a77e8fce6e3f2d80612a40bda6af8aabbe58b04041e8e342570decf9b339c84c583bf077a80a2fb648acd114be1261dd09fe30036bf8cf3289f605acbd24e5bc1e4899be27ebf9648b962aab233d5dd1ffe8a08cbae3841252e298f61ba39dd1ca7373177cc16a153ffabdf31b9776489d13c057239e0adbc2714b76efbda05c29cdad8403c762c7c680d71e92887756eaa60a9dd5fd292e0c5931fb58285ff6a63be1473c809c6d8768de596f9d36127b91f70f6e9b3253b94a952f77fbdd14d7e148926203b3b595988fe3e67a6342ab4b3c42a537b88127ace879e15c53ea1cb72e4759c771c2614178f40464def7b3114992a480d48e4bfd4b4406d317d2ba87960ab5ee4b8ee1e34163e5b16aa1dc35f53e20a2e39b191881aec12273564a25f924bb20c1584ee69e25cb50e0f2732457786aad9f5021229484b71975bc4d1ec3038536392cdfa304e515687c2485874dd0000000000000000000000000000000000000910141b2125";

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
        "QTX19ULH4FV9WHJ0UF8257GMZNESQF2DU3X5KGN2MJF8VRT3UE9G423Q9DCEP6"
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
