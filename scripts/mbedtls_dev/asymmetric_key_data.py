"""Sample key material for asymmetric key types.

Meant for use in crypto_knowledge.py.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import binascii
import re
import subprocess
from typing import Dict, Optional
import unittest

# No types :-( https://github.com/wbond/asn1crypto/issues/106
import asn1crypto.core # type: ignore


STR_TRANS_REMOVE_BLANKS = str.maketrans('', '', ' \t\n\r')

def unhexlify(text: str) -> bytes:
    return binascii.unhexlify(text.translate(STR_TRANS_REMOVE_BLANKS))

def construct_asymmetric_key_data(src) -> Dict[str, Dict[int, bytes]]:
    """Split key pairs into separate table entries and convert hex to bytes.

    Input format: src[abbreviated_type][size] = (private_key_hex, public_key_hex)
    Output format: dst['PSA_KEY_TYPE_xxx'][size] = key_bytes
    """
    dst = {} #type: Dict[str, Dict[int, bytes]]
    for typ in src:
        private = 'PSA_KEY_TYPE_' + re.sub(r'(\(|\Z)', r'_KEY_PAIR\1', typ, 1)
        public = 'PSA_KEY_TYPE_' + re.sub(r'(\(|\Z)', r'_PUBLIC_KEY\1', typ, 1)
        dst[private] = {}
        dst[public] = {}
        for size in src[typ]:
            dst[private][size] = unhexlify(src[typ][size][0])
            dst[public][size] = unhexlify(src[typ][size][1])
    return dst

## These are valid keys that don't try to exercise any edge cases. They're
## either test vectors from some specification, or randomly generated. All
## pairs consist of a private key and its public key.
#pylint: disable=line-too-long
ASYMMETRIC_KEY_DATA = construct_asymmetric_key_data({
    'ECC(PSA_ECC_FAMILY_SECP_K1)': {
        192: ("297ac1722ccac7589ecb240dc719842538ca974beb79f228",
              "0426b7bb38da649ac2138fc050c6548b32553dab68afebc36105d325b75538c12323cb0764789ecb992671beb2b6bef2f5"),
        225: ("0024122bf020fa113f6c0ac978dfbd41f749257a9468febdbe0dc9f7e8",
              "042cc7335f4b76042bed44ef45959a62aa215f7a5ff0c8111b8c44ed654ee71c1918326ad485b2d599fe2a6eab096ee26d977334d2bac6d61d"),
        256: ("7fa06fa02d0e911b9a47fdc17d2d962ca01e2f31d60c6212d0ed7e3bba23a7b9",
              "045c39154579efd667adc73a81015a797d2c8682cdfbd3c3553c4a185d481cdc50e42a0e1cbc3ca29a32a645e927f54beaed14c9dbbf8279d725f5495ca924b24d"),
    },
    'ECC(PSA_ECC_FAMILY_SECP_R1)': {
        192: ("d83b57a59c51358d9c8bbb898aff507f44dd14cf16917190",
              "04e35fcbee11cec3154f80a1a61df7d7612de4f2fd70c5608d0ee3a4a1a5719471adb33966dd9b035fdb774feeba94b04c"),
        224: ("872f203b3ad35b7f2ecc803c3a0e1e0b1ed61cc1afe71b189cd4c995",
              "046f00eadaa949fee3e9e1c7fa1247eecec86a0dce46418b9bd3117b981d4bd0ae7a990de912f9d060d6cb531a42d22e394ac29e81804bf160"),
        256: ("49c9a8c18c4b885638c431cf1df1c994131609b580d4fd43a0cab17db2f13eee",
              "047772656f814b399279d5e1f1781fac6f099a3c5ca1b0e35351834b08b65e0b572590cdaf8f769361bcf34acfc11e5e074e8426bdde04be6e653945449617de45"),
        384: ("3f5d8d9be280b5696cc5cc9f94cf8af7e6b61dd6592b2ab2b3a4c607450417ec327dcdcaed7c10053d719a0574f0a76a",
              "04d9c662b50ba29ca47990450e043aeaf4f0c69b15676d112f622a71c93059af999691c5680d2b44d111579db12f4a413a2ed5c45fcfb67b5b63e00b91ebe59d09a6b1ac2c0c4282aa12317ed5914f999bc488bb132e8342cc36f2ca5e3379c747"),
        521: ("01b1b6ad07bb79e7320da59860ea28e055284f6058f279de666e06d435d2af7bda28d99fa47b7dd0963e16b0073078ee8b8a38d966a582f46d19ff95df3ad9685aae",
              "04001de142d54f69eb038ee4b7af9d3ca07736fd9cf719eb354d69879ee7f3c136fb0fbf9f08f86be5fa128ec1a051d3e6c643e85ada8ffacf3663c260bd2c844b6f5600cee8e48a9e65d09cadd89f235dee05f3b8a646be715f1f67d5b434e0ff23a1fc07ef7740193e40eeff6f3bcdfd765aa9155033524fe4f205f5444e292c4c2f6ac1"),
    },
    'ECC(PSA_ECC_FAMILY_SECP_R2)': {
        160: ("00bf539a1cdda0d7f71a50a3f98aec0a2e8e4ced1e",
              "049570d541398665adb5cfa16f5af73b3196926bbd4b876bdb80f8eab20d0f540c22f4de9c140f6d7b"),
    },
    'ECC(PSA_ECC_FAMILY_SECT_K1)': {
        163: ("03ebc8fcded2d6ab72ec0f75bdb4fd080481273e71",
              "0406f88f90b4b65950f06ce433afdb097e320f433dc2062b8a65db8fafd3c110f46bc45663fbf021ee7eb9"),
        233: ("41f08485ce587b06061c087e76e247c359de2ba9927ee013b2f1ed9ca8",
              "0401e9d7189189f773bd8f71be2c10774ba18842434dfa9312595ea545104400f45a9d5675647513ba75b079fe66a29daac2ec86a6a5d4e75c5f290c1f"),
        239: ("1a8069ce2c2c8bdd7087f2a6ab49588797e6294e979495602ab9650b9c61",
              "04068d76b9f4508762c2379db9ee8b87ad8d86d9535132ffba3b5680440cfa28eb133d4232faf1c9aba96af11aefe634a551440800d5f8185105d3072d"),
        283: ("006d627885dd48b9ec6facb5b3865377d755b75a5d51440e45211c1f600e15eff8a881a0",
              "0405f48374debceaadb46ba385fd92048fcc5b9af1a1c90408bf94a68b9378df1cbfdfb6fb026a96bea06d8f181bf10c020adbcc88b6ecff96bdc564a9649c247cede601c4be63afc3"),
        409: ("3ff5e74d932fa77db139b7c948c81e4069c72c24845574064beea8976b70267f1c6f9a503e3892ea1dcbb71fcea423faa370a8",
              "04012c587f69f68b308ba6dcb238797f4e22290ca939ae806604e2b5ab4d9caef5a74a98fd87c4f88d292dd39d92e556e16c6ecc3c019a105826eef507cd9a04119f54d5d850b3720b3792d5d03410e9105610f7e4b420166ed45604a7a1f229d80975ba6be2060e8b"),
        571: ("005008c97b4a161c0db1bac6452c72846d57337aa92d8ecb4a66eb01d2f29555ffb61a5317225dcc8ca6917d91789e227efc0bfe9eeda7ee21998cd11c3c9885056b0e55b4f75d51",
              "04050172a7fd7adf98e4e2ed2742faa5cd12731a15fb0dbbdf75b1c3cc771a4369af6f2fa00e802735650881735759ea9c79961ded18e0daa0ac59afb1d513b5bbda9962e435f454fc020b4afe1445c2302ada07d295ec2580f8849b2dfa7f956b09b4cbe4c88d3b1c217049f75d3900d36df0fa12689256b58dd2ef784ebbeb0564600cf47a841485f8cf897a68accd5a"),
    },
    'ECC(PSA_ECC_FAMILY_SECT_R1)': {
        163: ("009b05dc82d46d64a04a22e6e5ca70ca1231e68c50",
              "0400465eeb9e7258b11e33c02266bfe834b20bcb118700772796ee4704ec67651bd447e3011959a79a04cb"),
        233: ("00e5e42834e3c78758088b905deea975f28dc20ef6173e481f96e88afe7f",
              "0400cd68c8af4430c92ec7a7048becfdf00a6bae8d1b4c37286f2d336f2a0e017eca3748f4ad6d435c85867aa014eea1bd6d9d005bbd8319cab629001d"),
        283: ("004cecad915f6f3c9bbbd92d1eb101eda23f16c7dad60a57c87c7e1fd2b29b22f6d666ad",
              "04052f9ff887254c2d1440ba9e30f13e2185ba53c373b2c410dae21cf8c167f796c08134f601cbc4c570bffbc2433082cf4d9eb5ba173ecb8caec15d66a02673f60807b2daa729b765"),
        409: ("00c22422d265721a3ae2b3b2baeb77bee50416e19877af97b5fc1c700a0a88916ecb9050135883accb5e64edc77a3703f4f67a64",
              "0401aa25466b1d291846db365957b25431591e50d9c109fe2106e93bb369775896925b15a7bfec397406ab4fe6f6b1a13bf8fdcb9300fa5500a813228676b0a6c572ed96b0f4aec7e87832e7e20f17ca98ecdfd36f59c82bddb8665f1f357a73900e827885ec9e1f22"),
        571: ("026ac1cdf92a13a1b8d282da9725847908745138f5c6706b52d164e3675fcfbf86fc3e6ab2de732193267db029dd35a0599a94a118f480231cfc6ccca2ebfc1d8f54176e0f5656a1",
              "040708f3403ee9948114855c17572152a08f8054d486defef5f29cbffcfb7cfd9280746a1ac5f751a6ad902ec1e0525120e9be56f03437af196fbe60ee7856e3542ab2cf87880632d80290e39b1a2bd03c6bbf6225511c567bd2ff41d2325dc58346f2b60b1feee4dc8b2af2296c2dc52b153e0556b5d24152b07f690c3fa24e4d1d19efbdeb1037833a733654d2366c74"),
    },
    'ECC(PSA_ECC_FAMILY_SECT_R2)': {
        163: ("0210b482a458b4822d0cb21daa96819a67c8062d34",
              "0403692601144c32a6cfa369ae20ae5d43c1c764678c037bafe80c6fd2e42b7ced96171d9c5367fd3dca6f"),
    },
    'ECC(PSA_ECC_FAMILY_BRAINPOOL_P_R1)': {
        160: ("69502c4fdaf48d4fa617bdd24498b0406d0eeaac",
              "04d4b9186816358e2f9c59cf70748cb70641b22fbab65473db4b4e22a361ed7e3de7e8a8ddc4130c5c"),
        192: ("1688a2c5fbf4a3c851d76a98c3ec88f445a97996283db59f",
              "043fdd168c179ff5363dd71dcd58de9617caad791ae0c37328be9ca0bfc79cebabf6a95d1c52df5b5f3c8b1a2441cf6c88"),
        224: ("a69835dafeb5da5ab89c59860dddebcfd80b529a99f59b880882923c",
              "045fbea378fc8583b3837e3f21a457c31eaf20a54e18eb11d104b3adc47f9d1c97eb9ea4ac21740d70d88514b98bf0bc31addac1d19c4ab3cc"),
        256: ("2161d6f2db76526fa62c16f356a80f01f32f776784b36aa99799a8b7662080ff",
              "04768c8cae4abca6306db0ed81b0c4a6215c378066ec6d616c146e13f1c7df809b96ab6911c27d8a02339f0926840e55236d3d1efbe2669d090e4c4c660fada91d"),
        320: ("61b8daa7a6e5aa9fccf1ef504220b2e5a5b8c6dc7475d16d3172d7db0b2778414e4f6e8fa2032ead",
              "049caed8fb4742956cc2ad12a9a1c995e21759ef26a07bc2054136d3d2f28bb331a70e26c4c687275ab1f434be7871e115d2350c0c5f61d4d06d2bcdb67f5cb63fdb794e5947c87dc6849a58694e37e6cd"),
        384: ("3dd92e750d90d7d39fc1885cd8ad12ea9441f22b9334b4d965202adb1448ce24c5808a85dd9afc229af0a3124f755bcb",
              "04719f9d093a627e0d350385c661cebf00c61923566fe9006a3107af1d871bc6bb68985fd722ea32be316f8e783b7cd1957785f66cfc0cb195dd5c99a8e7abaa848553a584dfd2b48e76d445fe00dd8be59096d877d4696d23b4bc8db14724e66a"),
        512: ("372c9778f69f726cbca3f4a268f16b4d617d10280d79a6a029cd51879fe1012934dfe5395455337df6906dc7d6d2eea4dbb2065c0228f73b3ed716480e7d71d2",
              "0438b7ec92b61c5c6c7fbc28a4ec759d48fcd4e2e374defd5c4968a54dbef7510e517886fbfc38ea39aa529359d70a7156c35d3cbac7ce776bdb251dd64bce71234424ee7049eed072f0dbc4d79996e175d557e263763ae97095c081e73e7db2e38adc3d4c9a0487b1ede876dc1fca61c902e9a1d8722b8612928f18a24845591a"),
    },
    'ECC(PSA_ECC_FAMILY_MONTGOMERY)': {
        255: ("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a",
              "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
        448: ("e4e49f52686f9ee3b638528f721f1596196ffd0a1cddb64c3f216f06541805cfeb1a286dc78018095cdfec050e8007b5f4908962ba20d6c1",
              "c0d3a5a2b416a573dc9909f92f134ac01323ab8f8e36804e578588ba2d09fe7c3e737f771ca112825b548a0ffded6d6a2fd09a3e77dec30e"),
    },
    'ECC(PSA_ECC_FAMILY_TWISTED_EDWARDS)': {
        255: ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
              "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        448: ("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
              "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"),
    },
    'RSA': {
        1024: ("""
3082025e
 020100
 02818100af057d396ee84fb75fdbb5c2b13c7fe5a654aa8aa2470b541ee1feb0b12d25c79711531249e1129628042dbbb6c120d1443524ef4c0e6e1d8956eeb2077af12349ddeee54483bc06c2c61948cd02b202e796aebd94d3a7cbf859c2c1819c324cb82b9cd34ede263a2abffe4733f077869e8660f7d6834da53d690ef7985f6bc3
 0203010001
 02818100874bf0ffc2f2a71d14671ddd0171c954d7fdbf50281e4f6d99ea0e1ebcf82faa58e7b595ffb293d1abe17f110b37c48cc0f36c37e84d876621d327f64bbe08457d3ec4098ba2fa0a319fba411c2841ed7be83196a8cdf9daa5d00694bc335fc4c32217fe0488bce9cb7202e59468b1ead119000477db2ca797fac19eda3f58c1
 024100e2ab760841bb9d30a81d222de1eb7381d82214407f1b975cbbfe4e1a9467fd98adbd78f607836ca5be1928b9d160d97fd45c12d6b52e2c9871a174c66b488113
 024100c5ab27602159ae7d6f20c3c2ee851e46dc112e689e28d5fcbbf990a99ef8a90b8bb44fd36467e7fc1789ceb663abda338652c3c73f111774902e840565927091
 024100b6cdbd354f7df579a63b48b3643e353b84898777b48b15f94e0bfc0567a6ae5911d57ad6409cf7647bf96264e9bd87eb95e263b7110b9a1f9f94acced0fafa4d
 024071195eec37e8d257decfc672b07ae639f10cbb9b0c739d0c809968d644a94e3fd6ed9287077a14583f379058f76a8aecd43c62dc8c0f41766650d725275ac4a1
 024100bb32d133edc2e048d463388b7be9cb4be29f4b6250be603e70e3647501c97ddde20a4e71be95fd5e71784e25aca4baf25be5738aae59bbfe1c997781447a2b24
""", """
 308189
  02818100af057d396ee84fb75fdbb5c2b13c7fe5a654aa8aa2470b541ee1feb0b12d25c79711531249e1129628042dbbb6c120d1443524ef4c0e6e1d8956eeb2077af12349ddeee54483bc06c2c61948cd02b202e796aebd94d3a7cbf859c2c1819c324cb82b9cd34ede263a2abffe4733f077869e8660f7d6834da53d690ef7985f6bc3
 0203010001
"""),
        1026: ("""
3082025e
 020100
 02818102d09661fc74224ba7be7907abef4f5e8bcc264a802c978f7eaa5855ada05436d75db768d20f68595dbcc3d725b138e80b247e44a4163a0542fab612acbbde45f2e93894aa253bddef6a7becdc9cc29a99bacf48dc6e38db7a33e9ac924c520fc6be7d6e5646c1d67fb8b2b97ac60beecc3bb8e75bed8315aa3fe46f748a66d6ef
 0203010001
 0281806a4a346beba97f655fe834647d2944f5f40815e7302caf02ed179893c2d989395d5e877cacbf24a77a079d3db71580ccdbf63023d00f80e52f5c1a0716b323b7bfcbdc8a1781c44c4153e3da228d17b2dc78eb1f44cff60fe1150808a6e38ba2470aee2e948a6898ddadea56d9470927aca8d94a0338c11a8e95715b5f94e011
 024101f5418534c36236fc9fd38934d7c06dfed3829151ccab56b6330c641f7796a71924cf8119ca26e186ecd3068d6607a05260db4857651980436891adde9eb92ab7
 02410170042fbdbaba1e102b7f7f1dc9d940cfdcd85dd0ea65f543c6432e9c5480724bb49b1e5f80ca2b9f84cd6644bfb2e3d0968090b89f534dc2951e606db909dd89
 0241014b6c1aeb1c14a04ec04e5975fb015cb914984c054dd22bef24299939c514733f88bb3a9d16b04685b3a883b8923190ab672715d9d31add57b4983de1e8087e59
 02410117bf76f308b0560e00a2c864427dcd50b5161c2aa523a00f46f4e6c79b4c90958fd2a282028aac227477169888085a38c34f33b3c41934f1071db23b75ff53d1
 02410120a428b4e0c4a6f202920fd49cc9886e6b6719d40a3ad0604f5d5efd5ef6973a573ab324f38ecb8e669a69341597081e240b6ae4e2714887dd78dadaeb0b9216
""", """
308189
 02818102d09661fc74224ba7be7907abef4f5e8bcc264a802c978f7eaa5855ada05436d75db768d20f68595dbcc3d725b138e80b247e44a4163a0542fab612acbbde45f2e93894aa253bddef6a7becdc9cc29a99bacf48dc6e38db7a33e9ac924c520fc6be7d6e5646c1d67fb8b2b97ac60beecc3bb8e75bed8315aa3fe46f748a66d6ef
 0203010001
"""),
        1028: ("""
3082025e
 020100
 0281810e62a76f0e0b59683a7ebf7cbfd37b1d1781d8f1b900604b507f0f04c72a3d340d067bcd53bea3caff4e4ae694f0b6d8f591a4167fbf7f372ab57e83a69a3f26f447bcf582bc9621a30a3b44d6b43e986d1a867b07489e4f9bfcadaa82a2782dc2729a631fb1fb9ffb794b4e53c76239e04d4a8f80352588db29462dde18237cf5
 0203010001
 02818101cfa0422e3bb60c15ef2e96db4499e789f5d634ea64567b2cdd6e2bdd121f85edccdee9b4ed178c5f33816101a7c371518b3e23f9fdc71b90242cd310b6b31428b0b64eb9596be0cc044cc85048982f90b706e66ccdd39ad5a1a7b64cf034eac0c35d7ace93f2bcd3ce243bd8f83b46f509ca2f805063002af2bb2d88b6ee36a9
 024103f0886d2977526f3f3f6a075600232ce3008517276dd3721dee08fd6c999fc976b9e8dd2bc143385fa4b48735ce81c66b501d7129ee7860cfbef23b5da91e6c2d
 024103a6c8734aace59d5f386f97de450f8a12d63ae6ac15d336e010c9fcf03a32f0611881ac6cd8b3f989925c0f025af26cf26aebd7d9b04eb503048dca2f503c28e9
 0241019b300451c3b47866f113e9a9c6a490c87c8dc6c2eca42902caea1f6907b97e0a4a02072aafc1185ae66c34345bddcd683361cda1aaf8a98009f9f8fa56d97081
 02401bcca849173d38e1e50ec48872ab54a2dcc621a80a7a1e8ea951287988718d5e85d90d64ab4926e9a575a168a385c421ad765813fc3f4af8cd00de7b6bba6e49
 0241036dcf69f6e548c8acfb536fb6cd186f8b8f20d313361d0447c1b5e380f4113e578b31e867dda47d44ad3761e793f725031b8d379f389de277a9a0137651df548a
""", """
308189
 0281810e62a76f0e0b59683a7ebf7cbfd37b1d1781d8f1b900604b507f0f04c72a3d340d067bcd53bea3caff4e4ae694f0b6d8f591a4167fbf7f372ab57e83a69a3f26f447bcf582bc9621a30a3b44d6b43e986d1a867b07489e4f9bfcadaa82a2782dc2729a631fb1fb9ffb794b4e53c76239e04d4a8f80352588db29462dde18237cf5
 0203010001
"""),
        1030: ("""
3082025f
 020100
 0281812b7cd197f5796d1f8e576b2b37723fd9210814ef1c1995f9899d50058f379d239c66878e922f34c6ae3672c8598fcd5d47b764d2ec156e134d03cf6a94d38d2ea8bc76dbbc60c4b974219090eaf287497d7dcf7f119cfa867496f7e91c12b5d552e1d1461a80dbe9a59db3b016c6c0141c3b2a0e226089b855cb88ef656408bd89
 0203010001
 0281810210d5ff531cacb22f8cf7dd1fd9fb0376f3647f2e9ab3df9c89b9ad3c98e68b89adeb29901dd2f2cf2ac1f817726278830ec8a8d0fdd19d496ec6bc683671174786b7d6a8e822fa71d65ad35abbdf0e6e55ff2c1821b62bc630192160e5c9b3dcafc65ae6b2a088fbc5591da58a45dd7a30960f7d3def75b80cdf73247360e8fb
 0241072e371a3ba861e78e3eb9313065faab0a97216e9544bfc2d5b403844b43273705755a85aa0baf7114770cfeca20bca17ac19bc4cbba106a33b3dddca0fb535f33
 0241060e6af37ab4ea11f52b9344e7160eb2a53f1075e1229a7f10a301de3359f53e981ea0e17df0fb380f089e5c37dd40daa29eefd205f5c87b38f8fef636b57ba053
 0241023a5dd09ef83540b30b554d24f64f9c28d212068cfc62ffe26d53b605e05557a632ee9e90cfc56531f36aadd82be63bb8aa405a04d8bbe5281bc45883fed7b4af
 0241041de6dbad4caf5417a9504965201c4b99827de8f369f7456a84b3ef5c4ec9238c7a3d782a8915ebec643a698b5bee0af0c243592bce0042aadeaf49a4b4c6dd9b
 024105d32dee952b503b536fcecf19ec08236a9cd945c49551bf99f15b674fc21aa199f4c4211f0f0007c417c1fb4155326a2142fca454bbd38d6dbc6caa7ac335a17c
""", """
308189
 0281812b7cd197f5796d1f8e576b2b37723fd9210814ef1c1995f9899d50058f379d239c66878e922f34c6ae3672c8598fcd5d47b764d2ec156e134d03cf6a94d38d2ea8bc76dbbc60c4b974219090eaf287497d7dcf7f119cfa867496f7e91c12b5d552e1d1461a80dbe9a59db3b016c6c0141c3b2a0e226089b855cb88ef656408bd89
 0203010001
"""),
        1536: ("""
3082037b
 020100
 0281c100c870feb6ca6b1d2bd9f2dd99e20f1fe2d7e5192de662229dbe162bd1ba66336a7182903ca0b72796cd441c83d24bcdc3e9a2f5e4399c8a043f1c3ddf04754a66d4cfe7b3671a37dd31a9b4c13bfe06ee90f9d94ddaa06de67a52ac863e68f756736ceb014405a6160579640f831dddccc34ad0b05070e3f9954a58d1815813e1b83bcadba814789c87f1ef2ba5d738b793ec456a67360eea1b5faf1c7cc7bf24f3b2a9d0f8958b1096e0f0c335f8888d0c63a51c3c0337214fa3f5efdf6dcc35
 0203010001
 0281c06d2d670047973a87752a9d5bc14f3dae00acb01f593aa0e24cf4a49f932931de4bbfb332e2d38083da80bc0b6d538edba479f7f77d0deffb4a28e6e67ff6273585bb4cd862535c946605ab0809d65f0e38f76e4ec2c3d9b8cd6e14bcf667943892cd4b34cc6420a439abbf3d7d35ef73976dd6f9cbde35a51fa5213f0107f83e3425835d16d3c9146fc9e36ce75a09bb66cdff21dd5a776899f1cb07e282cca27be46510e9c799f0d8db275a6be085d9f3f803218ee3384265bfb1a3640e8ca1
 026100e6848c31d466fffefc547e3a3b0d3785de6f78b0dd12610843512e495611a0675509b1650b27415009838dd8e68eec6e7530553b637d602424643b33e8bc5b762e1799bc79d56b13251d36d4f201da2182416ce13574e88278ff04467ad602d9
 026100de994fdf181f02be2bf9e5f5e4e517a94993b827d1eaf609033e3a6a6f2396ae7c44e9eb594cf1044cb3ad32ea258f0c82963b27bb650ed200cde82cb993374be34be5b1c7ead5446a2b82a4486e8c1810a0b01551609fb0841d474bada802bd
 026076ddae751b73a959d0bfb8ff49e7fcd378e9be30652ecefe35c82cb8003bc29cc60ae3809909baf20c95db9516fe680865417111d8b193dbcf30281f1249de57c858bf1ba32f5bb1599800e8398a9ef25c7a642c95261da6f9c17670e97265b1
 0260732482b837d5f2a9443e23c1aa0106d83e82f6c3424673b5fdc3769c0f992d1c5c93991c7038e882fcda04414df4d7a5f4f698ead87851ce37344b60b72d7b70f9c60cae8566e7a257f8e1bef0e89df6e4c2f9d24d21d9f8889e4c7eccf91751
 026009050d94493da8f00a4ddbe9c800afe3d44b43f78a48941a79b2814a1f0b81a18a8b2347642a03b27998f5a18de9abc9ae0e54ab8294feac66dc87e854cce6f7278ac2710cb5878b592ffeb1f4f0a1853e4e8d1d0561b6efcc831a296cf7eeaf
""", """
3081c9
 0281c100c870feb6ca6b1d2bd9f2dd99e20f1fe2d7e5192de662229dbe162bd1ba66336a7182903ca0b72796cd441c83d24bcdc3e9a2f5e4399c8a043f1c3ddf04754a66d4cfe7b3671a37dd31a9b4c13bfe06ee90f9d94ddaa06de67a52ac863e68f756736ceb014405a6160579640f831dddccc34ad0b05070e3f9954a58d1815813e1b83bcadba814789c87f1ef2ba5d738b793ec456a67360eea1b5faf1c7cc7bf24f3b2a9d0f8958b1096e0f0c335f8888d0c63a51c3c0337214fa3f5efdf6dcc35
 0203010001
"""),
        2048: ("""
308204a3
 020100
 0282010100f7bb6b8eab40491cd64455ec04d4ed8db5051a9738fc7af73ff3b097511cce40aaf76537b1353504427986b7b2b53a964a6937b558ec0d1dea274af2b8fff2f094c243fa577266a79db0c26ffe30416d23ef05dd5fecab413ebbb4f8526ae720a94584226b37d92ef463fc736cb38e530e7488d9162f5726807bc543138a2d258adb4d680221c2532381ccfa81bc89bc3d7b84039c2df41ce3ec8db91c2380e781ba3aa9e23b74ed9973d4908efca47aa8d9b7b0a4423297a404427c3f3cd6e0782e4553880f06ba39a64f4a7b0eef921a6050a207cefadcf07394a3e18ea915dc8497e7ae61fc3162f62f5065a692af077266f7360c2076cebeaf14cb22c1ed
 0203010001
 0282010000b8962dce604bc62e7678f48ca80cfff456ad36e2f6d329cc911a42ba7cf5b9b8f5aae1005e4a06f6e591279038d8508f2b62badfa5223da3cc94fa8360d5556f6d6852be75ea08135cac1834da719a4e7837e166d1d2c6c816b64661c10766b02f705cc4489f947428255835a909214341c21335ae12181dd81e611d59b1db70667bebd7e92b71e1d388318d3ec14d616f72c231f6727a183e6818285bd65f6572cadc9012248821b2d0ae6cedd30ca440d4d34cd77e2cf6b40ed2c7d856b30d474733fce0fb695c3e6530c079aed955e4073055f2655d4b671e291fde400f2f06d0b33f87d261e0ad3dae48a913841b34cfed03790fcaee00de2e90fb9621
 02818100fcbe89cd1aa319e49ef4f72149bf06da57dcc64d3de605e9ff3e76fc66f4b1e2878245ffd71990511b17e97f33818889a8c21b5527fd181327affe88f9bba670c4e6f1e6309bd0323074e4cbcf23dce3c19b8d5495f56a93059ba7414f28ed1ec906ad18c63de1148abcfe9be7986000f425e580b70e43e48e24fa9d51aaae4d
 02818100faec5a7bed2e53cfca1e167db4641db5a00fe2c328125423d594789f3ec072c623e7afbdee0089fd26307651f6d3611a88af28c34585d5cb713a650c35933f58944db9bd15ba9fc28b07e6705b7b3ef1ccb48d21a53569c8b84c444b61ea5c6e67b54f0afd852ffb8c92a111fab8677263eeb80cf1a3403b4a9a209776947221
 0281802ff99afeabc7b9ea83a1cc272d706d4494d8fb6b3e0ca3a2bf28843d74ed8db68a3258472ff5524792f4ff057e296059810717591ab61813cabcc57c0aab6bf48bebaa8f1f3af45212909dbd721c449996ee87ed3e69cf49090f7ab812e699dbf61ca64ec592895ef4d6db1d8ce08798a6bf6ac8fbf6613cc91e8bd3c0e4bd21
 02818100b29b34590bddb308afecb4c3ab78abf1114add755e7b956aa0677b6896a933c937db7dabaad2b565fd1df7caa5ef9629e5eb100fd6d7c9f372d846fee6cfb6025e25e934df57a4ca3c5e5637d9d6235ac80428852f6c92acae0a937e38e731fde0521d3e4c70d653ae9edc89c8b623e4379fbf606f4b6db8068528f7c70f2921
 0281800ed47ae05b275a23a7dfe3ffb727e3a268e626a59d401d2d846de26954ff54fc9ed93a9af33fac2c967a18e0f86145083e39923454bc10da5f4937e836b99851956bffb301ce9e06789786693213fcde6d5f2933d52bb29dc340ea011257788d3c5775eb6569230aafbf08752d40a8419de71b01d4927e27c1079caada0568b1
               """, """
3082010a
 0282010100f7bb6b8eab40491cd64455ec04d4ed8db5051a9738fc7af73ff3b097511cce40aaf76537b1353504427986b7b2b53a964a6937b558ec0d1dea274af2b8fff2f094c243fa577266a79db0c26ffe30416d23ef05dd5fecab413ebbb4f8526ae720a94584226b37d92ef463fc736cb38e530e7488d9162f5726807bc543138a2d258adb4d680221c2532381ccfa81bc89bc3d7b84039c2df41ce3ec8db91c2380e781ba3aa9e23b74ed9973d4908efca47aa8d9b7b0a4423297a404427c3f3cd6e0782e4553880f06ba39a64f4a7b0eef921a6050a207cefadcf07394a3e18ea915dc8497e7ae61fc3162f62f5065a692af077266f7360c2076cebeaf14cb22c1ed
 0203010001
"""),
        4096: ("""
30820929
 020100
 0282020100cc8725f6b38d5d01aeeb07d36e03de4d31a0261ce74fe11a895ecfd13d168aee932af135ffbb849877273897081f3f7593c14ae82bc266c10544f726ae1ccf133d8a4018d380dfa25251c011107b7513a943346aa0e0dec11d8d7fa25644653c118daabce6d41f066f6621768801478055780e91b68ea3c95856d172a89032b39c824e8b7dc1a3f8aee4f6b368baa3cd68f50d52680117e9b913d7f8c852a0d1008e8b87a5c97e37afc11a080550557b8b4dcbd8e192ed3366d83a09d27c77e150f66855b5dcfdb2df151bd7f444250eaf6fe3f236826c81fa848101bfaad535ffb522d6ff97c9dd1e43b82cce2921d153c15450c4724ffd3efdca578e013650a03a5cf501fc58600fb5c860c0ef0cfe0ac0712d441313dca41a4d7d411e6c83b2151749d28be4692f62373db07e4a79051c5682ec20d491c4cfc7bc140f35fa15e5a1fa756d65b8ef93addf4c47c4a35b184f22a1ef089948f946f6faeb6470f26746e658cf9b4177417842e6d373558089aff721b930e9ec61b4f6a02c052c6924d39a5bbb15ed1106c4010f4dd69c79d042c8b31661b1ee486bc69db5f2f07a50d85b20699d601315625bb869629c7f4c5d48b211d097f438acec95973a38d421090af0f13484e4e94b8cb5efc18507f4b931df39987ffb2830293e4da381aaf70b3292952ef934e2b40fdebba3d9701b76e1be548274b2602d888537482d
 0203010001
 028202001a943e9c0089f0aa0116048a96abb486321a86916f82fb352460789fcfb1400550853e5afedc9ad6e877259cc4feb093c24b968534f89abb5f48aed8ad3c4bb1cba7cd7c1c724d3dae36770010b5068a334f2b3ee720c9f9ed320001f3f587f5662f939e605df519343d60c0635ccd32b188bc55f5d434173c9e6db2199341af833990e50246f99cddf79dd2c35babe14c103a76b8d2d98d73528f98c249b0a1f09155b31f599fc833542422a2342623bbbef4ac7ee605e2cdecf01fea25683bd4f66ca924ccef00418adff730c4714f66ffa2af0da3e5df7f539c634289fc12bc24093ec8f0ec180af0907cec1ebec911fa180fb5f3c80ed852896ad6e6b3eccb44de62193d52118cab2b171071d5fdaa7c4288fc7766d57774f4be46151bb90ace7c10c215f62ed26e52e6122436f532bd54fc08272adb216a2db433d5699c40ad58faa2660898ffccfc98002f8bb0361b4cf9ed6e93c1ca96d34a1ef40460f85918cfde4a8193b51ecea4b3903cae924a8fad5f8308954c9f19a7597bf0a75126a557e49f8bbd31fc4e8556f230640bf36204c6cf3d56dca5a41d860307ba6705a698681100a327f91739c486c470ba71d03d285314b0d7d04008e03f2a2b85e7c243d6fd9b97a02168c069ec572d3f0ca15ebcb1739f3a0b3c147a88e0b74f45a007ae927d6f822bf50b87b1e93fe7d9180bc6bc12bde6c8070d10c97331
 0282010100f50ebceac9d3c64482a8c265d6365461aa4a31a6a7633a24c8e34794ecdfcab1d6b52fb6a5f38055cc32d6a61b889550de27b3d0bd68b6d4fda041598ab98887143988576806b1c48720794902952ebe1bf0def65a0e6f94067056e6864fa2882e3a16f246282093d037639078182dd0a6eb21d3bad0637901a268b14c632c9d0b1690ed88abdde03f528247aa2e41557d0865ad34e53ff53ae0e5dea195d93fe65c25871f6f23adf34b6e960c2978f2b7475dafce6cbb26a53934d26c193d67f32de91035eeb89022beb7d5df784ac20ca6ab91bf6b775b6c9416f605b4841736cbfbd22ad98ab2e8428457e0793f5af40e550b48765d59e6e1b4a4a1f571f1
 0282010100d5a91d4d44bb9b73c1fe0248925e2c0ec1de51390bd8a73b453da51ae29325ae7657089fd4ee4a2fd96e345b57f672d7d484fde99189ab0a6365bf2b38680d6bb947f4b217be660323c26b86d643ae686d82e36ec00cfd038942443caa04a0f91e68ec717935b45e790311be56440d7176949594688ed1dd5c9103c57c158d05e4c37b98d81898030744a64f6ebdbf750aab79757e34dac422163ea7c0f42b97710c861978b24100385aad727e5f3836a74ea4bf1d36ef2a5edf9c9e8f996ef3191348450ea9f1d4a63db29cb06f63e5badb18e4d40f5112b658d1cc23cb65388aca03d141a6bc5fbd9429fe33d340d3e85bfa848908d60b562f894e8a337dfd
 0282010100c4950f0d95dc51d791ad094d223b3113abc49af1e2a361f83242c8a07a28c8744315d3f1c44c82edd0c21398eacb75648ae1f48885f92379d6ffa08cd11126a99d9acd79b8946e3486659185f511718ec5e1432b02714426cdc77e9eacade36735161a643dcd60dcd2922c47af5f4e196c5d8124555f67fca148048dfe062cbaca334f0d8daeb96d73be9f8e17c1c55d6bd0b9a7e99fe1dfba5cc16a07dbaa8c6d220c64c9dda114a0f029052b3a75b0d73fe3b2ed7821e5cd7307a1a95fd1f7ba8760c8454b7c38fbf65c88b01cd273ba2c55c3b477e426ae025a2cffc4a095f2ba4e0779a24b765b85489f2a0e79b95fc0c38e2a91f12ef65ca749ce369431
 028201002aa48e0c95e33bab66d4637048863314deec9819629be30499552c56a951e4fb64f309ed9c79d2a4aa28ac9a6e7be97fda1290fac4e94d11cdb4c8eabf5f450e72f4418a29e2fe493221e3840dcf8447a353b440ae63e93b83718e5ced31ef4ec91af7d5cdf3420478f27be019278be7515b665f305f10d3b55ddbfad64116dc4e4415aef3b234e4a5d6b5bab4c77a26c9f25f536bd4f0b4a478fc184f126c80d53742ac62c270e6b258a6b56b3365ecc28797a9ed12c1b91b265603ef751807bcc1747313f22729e1e3fe79f75cc3fb5dc7ccb81efacf9b847945a6109ecf9cf156505cbb55a3d317eb325661d18fe6bb416046837318053b365199334c03a1
 0282010100ee63706030a4ece9fe3bddcfc49f5a83f37f63ebcb29dbdc999f6ff54b596f115cf1eca09990108a439518e996f689fdde89b2c67edc04bf8e366734c2ae3017ec14e042050e7c656840146ca048394dcebe90dd2195349bbad306569031b2ef6e9171d2ae7797c8844e548394ca3b768d8496e99ef63abb59b0ff7fc70eb53153dd0f59018a275acba701f2c76a15c894f53461fedf65bc25c2c5cec396e556a1a919bc7a056393d50644126dcdef9256642e65a6043cbce9497e192cf2cb33648e117f41dbf01900acb93b0c78ddf31f381f4db3f9ccbbb69093dabf2e89dbbc0cb72f20c005a2519e3a874146495d7aacf3416a422e560986f22f39456e7f
               """, """
3082020a
 0282020100cc8725f6b38d5d01aeeb07d36e03de4d31a0261ce74fe11a895ecfd13d168aee932af135ffbb849877273897081f3f7593c14ae82bc266c10544f726ae1ccf133d8a4018d380dfa25251c011107b7513a943346aa0e0dec11d8d7fa25644653c118daabce6d41f066f6621768801478055780e91b68ea3c95856d172a89032b39c824e8b7dc1a3f8aee4f6b368baa3cd68f50d52680117e9b913d7f8c852a0d1008e8b87a5c97e37afc11a080550557b8b4dcbd8e192ed3366d83a09d27c77e150f66855b5dcfdb2df151bd7f444250eaf6fe3f236826c81fa848101bfaad535ffb522d6ff97c9dd1e43b82cce2921d153c15450c4724ffd3efdca578e013650a03a5cf501fc58600fb5c860c0ef0cfe0ac0712d441313dca41a4d7d411e6c83b2151749d28be4692f62373db07e4a79051c5682ec20d491c4cfc7bc140f35fa15e5a1fa756d65b8ef93addf4c47c4a35b184f22a1ef089948f946f6faeb6470f26746e658cf9b4177417842e6d373558089aff721b930e9ec61b4f6a02c052c6924d39a5bbb15ed1106c4010f4dd69c79d042c8b31661b1ee486bc69db5f2f07a50d85b20699d601315625bb869629c7f4c5d48b211d097f438acec95973a38d421090af0f13484e4e94b8cb5efc18507f4b931df39987ffb2830293e4da381aaf70b3292952ef934e2b40fdebba3d9701b76e1be548274b2602d888537482d
 0203010001
"""),
    },
})



class ECPrivateKey(asn1crypto.core.Sequence): # SEC1 §C.4 (subset)
    _fields = [
        ('version', asn1crypto.core.Integer),
        ('privateKey', asn1crypto.core.OctetString),
        ('parameters', asn1crypto.core.ObjectIdentifier, {'explicit': 0}),
        ('publicKey', asn1crypto.core.OctetBitString, {'explicit': 1}),
    ]

class RFC8410ObjectIdentifier(asn1crypto.core.ObjectIdentifier):  # RFC 8410 §3
    _map = {
        '1.3.101.110': 'X25519',
        '1.3.101.111': 'X448',
        '1.3.101.112': 'Ed25519',
        '1.3.101.113': 'Ed448',
    }

class AlgorithmIdentifier(asn1crypto.core.Sequence): # RFC 8410 §7 (subset)
    _fields = [
        ('parameters', RFC8410ObjectIdentifier),
    ]

class OneAsymmetricKey(asn1crypto.core.Sequence): # RFC 8410 §7 (subset)
    _fields = [
        ('version', asn1crypto.core.Integer),
        ('privateKeyAlgorithm', AlgorithmIdentifier),
        ('privateKey', asn1crypto.core.OctetString),
        # openssl (as of 3.0) doesn't support bundling the public key
        # with the private key.
    ]

class SubjectPublicKeyInfo(asn1crypto.core.Sequence):
    _fields = [
        ('algorithm', AlgorithmIdentifier),
        ('publicKey', asn1crypto.core.OctetBitString),
    ]

class TestKeyData(unittest.TestCase):
    """Check the key data through unit tests."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # The field maxDiff exists in this parent class, even though
        # for some reason pylint doesn't find it.
        self.maxDiff = None #pylint: disable=invalid-name
        self.openssl = 'openssl'

    def assertBytesEqual(self, #pylint: disable=invalid-name
                         first: bytes, second: bytes,
                         msg: Optional[str] = None) -> None:
        """Assert that two bytes objects are equal.

        In case of failure, show the differences with a hex dump.
        """
        first_hex = first.hex()
        second_hex = second.hex()
        self.assertMultiLineEqual(first_hex, second_hex, msg)

    def check_key_pair(self, pair_der: bytes) -> None:
        """Check that the DER representation of a private key is valid.

        This both performs a slightly loose syntax check (allowing
        multiple formats and trailing garbage) and a validation of the
        correctness and consistency of the internal values (public values
        match private values, etc.).
        """
        check_result = subprocess.check_output(
            [self.openssl, 'pkey', '-inform', 'DER', '-noout', '-check'],
            input=pair_der)
        self.assertEqual(check_result, b'Key is valid\n')

    def check_public_from_private(self, private_der: bytes, public_der: bytes) -> None:
        """Check that the public key is valid and consistent with the private key.

        Both keys must be in a DER format accepted by openssl.
        """
        public_from_openssl = subprocess.check_output(
            [self.openssl, 'pkey', '-inform', 'DER',
             '-outform', 'DER', '-pubout'],
            input=private_der)
        self.assertBytesEqual(public_der, public_from_openssl)

    def ec_weierstrass_get_oid(self, family: str, bits: int) -> bytes:
        """Return the DER encoding of the OID for the specified curve.

        This function only supports curves known to ``openssl ecparam``,
        which excludes Montgomery and Edwards curves.
        """
        bits_for_name = bits
        if family == 'SECP_K1':
            if bits == 224:
                self.fail('PSA uses 225 for the bit-size of secp224k1')
            if bits == 225:
                bits_for_name = 224
        curve_name = re.sub(r'_([a-z][0-9]+)\Z',
                            lambda m: str(bits_for_name) + m.group(1),
                            re.sub(r'brainpool_p', r'brainpoolP',
                                   family.lower()))
        curve_name = {
            'secp192r1': 'prime192v1',
            'secp256r1': 'prime256v1',
        }.get(curve_name, curve_name)
        oid_der = subprocess.check_output(
            [self.openssl, 'ecparam', '-name', curve_name, '-outform', 'DER'])
        return oid_der

    def check_ec_weierstrass_keys(self, family: str, bits: int,
                                  private: bytes, public: bytes) -> None:
        """Check the correctness and consistency of EC Weierstrass keys."""
        oid_der = self.ec_weierstrass_get_oid(family, bits)
        oid_asn1_object = asn1crypto.core.ObjectIdentifier.load(oid_der)
        pair_asn1_object = ECPrivateKey()
        pair_asn1_object['version'] = 1
        pair_asn1_object['parameters'] = oid_asn1_object
        pair_asn1_object['privateKey'] = private
        pair_asn1_object['publicKey'] = public
        pair_der = pair_asn1_object.dump()
        self.check_key_pair(pair_der)

    def check_ec_rfc8410_keys(self, family: str, bits: int,
                              private: bytes, public: bytes) -> None:
        """Check the correctness and consistency of EC Montgomery or Edwards keys."""
        letters = 'X' if family == 'MONTGOMERY' else 'Ed'
        number = '25519' if bits == 255 else str(bits)
        oid_asn1_object = RFC8410ObjectIdentifier(letters + number)
        pka = AlgorithmIdentifier()
        pka['parameters'] = oid_asn1_object

        # Check that the private key is a valid value.
        private_asn1_object = OneAsymmetricKey()
        private_asn1_object['version'] = 0
        private_asn1_object['privateKeyAlgorithm'] = pka
        private_asn1_object['privateKey'] = asn1crypto.core.OctetString(private).dump()
        private_der = private_asn1_object.dump()
        self.check_key_pair(private_der)

        # Check that the public key is correct and consistent with
        # the private key.
        public_asn1_object = SubjectPublicKeyInfo()
        public_asn1_object['algorithm'] = pka
        public_asn1_object['publicKey'] = public
        public_der = public_asn1_object.dump()
        self.check_public_from_private(private_der, public_der)

    def check_rsa_keys(self, bits: int,
                       private: bytes, public: bytes) -> None:
        """Check the correctness and consistency of RSA keys."""
        # Check for strict ASN.1 compliance, including the absence of
        # trailing garbage.
        asn1_dump = subprocess.check_output(
            [self.openssl, 'asn1parse', '-inform', 'DER'],
            input=private).splitlines()
        # Check that we have a SEQUENCE of 9 INTEGERs, which is the
        # concrete syntax of RSAPublicKey.
        self.assertEqual(len(asn1_dump), 10)
        self.assertRegex(asn1_dump[0], br'\A[ 0-9:=a-z]*: SEQUENCE *\Z')
        for line in asn1_dump[1:]:
            self.assertRegex(line, br'\A[ 0-9:=a-z]*: INTEGER *:[0-9A-F]+\Z')
        # Check the key size, which is the bit-size of the modulus.
        modulus_hex = asn1_dump[2].split(b':')[-1]
        self.assertEqual(len(bin(int(modulus_hex, 16))) - 2, bits)

        # Check that the public key is valid and consistent with the private key.
        public_from_openssl = subprocess.check_output(
            [self.openssl, 'rsa', '-inform', 'DER',
             '-outform', 'DER', '-RSAPublicKey_out'],
            input=private)
        self.assertBytesEqual(public, public_from_openssl)

    def check_keys(self, psa_type: str, bits: int,
                   private: bytes, public: bytes) -> None:
        """Check the correctness and consistency of a key pair and a public key."""
        if psa_type == 'PSA_KEY_TYPE_RSA_KEY_PAIR':
            self.check_rsa_keys(bits, private, public)
            return
        m = re.match(r'PSA_KEY_TYPE_ECC_KEY_PAIR\(PSA_ECC_FAMILY_(\w+)\)\Z',
                     psa_type)
        if m:
            family = m.group(1)
            if family in ['MONTGOMERY', 'TWISTED_EDWARDS']:
                self.check_ec_rfc8410_keys(family, bits, private, public)
            else:
                self.check_ec_weierstrass_keys(family, bits, private, public)
            return
        self.fail('Key type not recognized: ' + psa_type)

    def test_key_data(self) -> None:
        """Test the correctness and consistency of the entries of ASYMMETRIC_KEY_DATA."""
        for psa_type, per_type in ASYMMETRIC_KEY_DATA.items():
            if '_KEY_PAIR' in psa_type:
                # If there are private keys of a given type, there must
                # be public keys of the corresponding type.
                public_type = psa_type.replace('_KEY_PAIR', '_PUBLIC_KEY')
                self.assertIn(public_type, ASYMMETRIC_KEY_DATA)
                for bits, private in per_type.items():
                    # If there is a private key of a given type and size,
                    # there must be a public key of the corresponding type
                    # and the same size.
                    self.assertIn(bits, ASYMMETRIC_KEY_DATA[public_type])
                    public = ASYMMETRIC_KEY_DATA[public_type][bits]
                    with self.subTest(type=psa_type, bits=bits):
                        # Check the correctness of consistency of the
                        # private and public keys of a given type and size.
                        self.check_keys(psa_type, bits, private, public)
            elif '_PUBLIC_KEY' in psa_type:
                # If there are public keys of a given type, there must
                # be private keys of the corresponding type.
                pair_type = psa_type.replace('_PUBLIC_KEY', '_KEY_PAIR')
                self.assertIn(pair_type, ASYMMETRIC_KEY_DATA)
                for bits in per_type:
                    # If there is a public key of a given type and size,
                    # there must be a private key of the corresponding type
                    # and the same size.
                    self.assertIn(bits, ASYMMETRIC_KEY_DATA[pair_type])
                    # The correctness of the public key is checked together
                    # with the private key.
            else:
                self.fail('Weird PSA key type: ' + psa_type)


if __name__ == '__main__':
    unittest.main()
