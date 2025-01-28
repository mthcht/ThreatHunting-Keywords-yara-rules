rule Dataplicity
{
    meta:
        description = "Detection patterns for the tool 'Dataplicity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dataplicity"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string1 = "/bin/dataplicity"
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string2 = /\/dataplicity\.app/
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string3 = /\/dataplicity\.conf/
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string4 = /\/dataplicity\.log/
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string5 = /\/dataplicity\-agent\.git/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string6 = "/dataplicity-agent/releases/download" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string7 = "/etc/dataplicity"
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string8 = "/opt/dataplicity/"
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string9 = /\\dataplicity\.conf/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string10 = /\\dataplicity\.log/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string11 = /__dataplicity_remote_directory_scan___\.json/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string12 = "0380372a475147bed23ba4b24891c843de3d3391f2ee40469a994df38b427115" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string13 = "084e9d9e599fdff366099956e1821219c2e0004974fc240a5033d66afed32d36" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string14 = "0bbef44b2adaf9275ffdcc5d8a7bb65a31208c3909bde623487caf83680f19c9" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string15 = "0dc142c2d3aeb026b3e4c48a625a914cce46ff7746ecf4b0f14e5eec3943e2ac" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string16 = "0e0eb55f19ba1ca1758d6a10250d53ba6518180eca89545a90f5cce81a3729b0" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string17 = "0f03b1686c53f818f1688e4f39c2856c1407446db1a13d1791e500ce90db5dbe" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string18 = "0f99b8c3d94d5252864d53bdba47a9f8ec6c710dbbcaf1070b4467822773d14a" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string19 = "1555e71932fad726781cc977ee8cc22fa7eab9d515255c81c1a711668dde5e6d" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string20 = "19e8ff4b933c50b4eabdd8dd6bddea9f34ab1d4b1155d3e885ef49ff480a6912" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string21 = "1abd5cde54ace5237b1921db031fa2bf01ff61af1025384dd82042b047b3f94f" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string22 = "1cc170b0e7ab93a5624909c533cd70df630e60c199ad394b050658d19807537b" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string23 = "29d9ce86776a65e5b326487953fe5aa52510855524f9795c9c2034915620019c" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string24 = "2d4849ea0fa996daefaa35cd0a3a4f62c49a6aa9b1b493ef2cfb4df2e89acf23" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string25 = "33420ebb3630aadbca112f47b772f4557e7a2c94ec6d6e149c94a58647cc4f89" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string26 = "3488de41725dc14d6140e5f547836af19402922776413bdd584acd0c9df254e8" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string27 = "364440d6c449fbc8befdf3b510891e2d6e99eb5ca4a5d151d1fc5ae8deb6a3e2" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string28 = "4351d255c804e04bf047407c30ef1f96fa3930fa4ffb0891d0007d232957a87a" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string29 = "4668623f3ac867b7edd563e139dff0bda23393199629d5b8c5499328999ed7ee" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string30 = "52f61a3c39aa3f8498648436cb20602f6ddacd0b245ad611cec68057793fb360" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string31 = "552d20cf969e7b8503c12566552a70c2956e1476a8b6a24f31056ae3ec6eb2b2" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string32 = "55a0a2935fd0577e16c3e6f2b17a29839a6c58e6057830fa0c125945759cf397" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string33 = "5772da1ce34daccb2ff7854cc83c6f37321041b8b103d047bdb77e4ecc031113" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string34 = "587f5b4be33a2f66eb23329d57ebf8383de3b5ab30096b048bcc0eaf3b9ae310" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string35 = "5bfbd898b6368c600e44b9cdff5ec284e4ca7131c2eb0c281c5d641a325b632b" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string36 = "6202bf76f1aa853d1b5172902fba67901aa3f00719f3ca5e8c8a57f5819b5797" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string37 = "641baf9a4a2bba8174395d76d675682a8d9471ff722d84c1892e9bdd8a03d15d" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string38 = "69717f46c90721f550e466c0bd7708bfbc004749d49a784a7ae73cc11cd272e0" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string39 = "6a23cc94b17569d60f0fb9f3fb1fac721c5763d85931b399afcc45540b8a1f75" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string40 = "6c96dc136639c1bad445138519d0a4737d36195a32d7b36048b4778b0b9a69eb" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string41 = "6df1812ceb5b98224890e3b48d458c94a0c486cbeac4f9cde750ef7954d85569" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string42 = "6efd0a501a91178a31ae82146c8ed8b1d91b2a62e8e8ea644e80b7562846dbb1" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string43 = "765718d9c62be08268c07697433430055a1c212d33d09049e6c4f3207d140b23" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string44 = "79214ac3ae4f23ca7fbe8325ef3d0148d06ea39ad95b08182e9e7b0264ad7bc1" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string45 = "79463fd2757c244075372066f2c6734c7bad99014ce4d133a73ecab3d4763c66" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string46 = "8285531c07766ad9297296d9a466746b3bcafff13ceb39d374422f254f2d00d0" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string47 = "8c00683c5e735117c8970664ff145273733c5d53c630489c52461ab3730ed1ea" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string48 = "8e300a72a7e181e970c8fd89e9c5678c3083ef72a9ab61378b61b5159c23713d" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string49 = "931899dfc6ec5692d5795ff883ccd8353f65ffbbbb4fd2edd7eefd02fe61aa8a" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string50 = "937e41a72f88eb49c60782807ff44014c16d4ccf348d4ddd03741124ac7cab8d" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string51 = "9697ee3ddb8efa374f1efcdafaf21849173831c6b3ab5eee5d11d551b58778ed" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string52 = "9b5afa6ac3aadfbfd33f053fdfd1808175b2e4767503f957e81004b54ff70a25" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string53 = "9e0fcc92b00eb9657979f4492584959b702e5d3f3e50c3cdb4a55c76f55693a7" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string54 = "9f5839d8901177b6ba08b744d561d51a8c4fb8ae7e492cf2e4408b90e49497df" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string55 = "aaf1d0a58fe9fa1978beb4f2ea62fb6082e467b1e14e3f0164a6566d9d2ec6ad" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string56 = "ace15d24a354ec662a6e252fed6cf772de113efb57bbb390e1ac1b85f3f4c285" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string57 = /api\.dataplicity\.com/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string58 = "b2834369b18687b609ec6f0b3fda7dbdf89fb55301b50cf110702995970d13fe" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string59 = "b2ef7165622db32fdb1b2117f9393fc549bfe5fe9e7541a619a5707d2179d81e" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string60 = "b9a70c3eac6f54cd95d0a61e74e0d12a1c93a21cd5d14d4aab53238e6a8f2236" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string61 = "be6180600783794df523f8c180917acc285d3bbf98e9b2edad19175771f390b7" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string62 = "bee3b667e865fa5552261f7fa7df260ffae18980c0e827c918180f969fac2b51" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string63 = /bit\.ly\/2alyerp/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string64 = "c20b795433e8799d5ef176aecd7efab4a3db7849637d8ce5f9fd0cd3ac04590f" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string65 = "c2f078339cc05f64a6742db6750142008627e558c1c4680ef266fdb1be836f48" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string66 = "c33d855091e67c7d51b7792a1875d2a98268ac8a4b160aca2784d7062077597e" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string67 = "c5c796d6c73f103b42ee079472d4717829cd71990ff722de42672a73c80a8d7b" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string68 = "cf8ba8220acc8d2af85040b65bd3b8af72a315ce6ba3da1f0d1f73b21cbd3411" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string69 = "d1d5d89ce34a0d1683d455a17c9dad480160e4b55bcf82fa231f41c19938b0d3" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string70 = "d2fa6048dc937b573fa2320647f97cbef00d74286c9e8f363b97463de92bcd75" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string71 = "d36f3421f55defb2882bb80dfb40367335953a7b54d0275c14ca99a2c0c47c6b" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string72 = "d55689c6b7dd5abf42d07d297208abc256fcc57fea22d806d16b0d41650dbe70" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string73 = /dataplicity\.portforward\.Service/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string74 = /dataplicity\.subcommands\.run/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string75 = "e29ac4e7c3603251b1d04f9d4ec29809f558efa7b6aff5be6b3c780d145387e3" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string76 = "e5866c7ffaffc7c1cfb1ec9c259ca3ba600167bd2907c77cd3c68cd6b647f3a9" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string77 = "e7ebcee1c02d30c722b9fbb6d875a8c6ce17525ea2f8b2bd5766c36233af8bc4" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string78 = "ead10a59018c96967138f47da9484c577d80caa251a0769cee65910bdfd10fea" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string79 = "eca853ac05aff10c633c1e2c7b8edf1e2caf493ddf54145e908049f2f532fe26" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string80 = "f02191ca0c8ae1b43bf43bcd075713f1728d96dcfb238b44d812a1864389bf5d" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string81 = "f0b3b07c44622aeae797eb9938fa2e1e38736894e4ed99a527c84a1ce0b74475" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string82 = "f4fc57d8f4a00945dda67548d12bb77bc69bf24c45b8a724a63e83274d0eca2c" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string83 = "f79bf7ee90db6c16f7032a289e49ec0ba08d50f77d35ce78432daeb62a2ffd74" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string84 = "f9d54726a0c5ad3cfb56945dd52fd50252afce25700d0156ab37c3cfa05a25a2" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string85 = "fa97d200632ae98bce658b921c12db494ad1619223831849665a160d98ed541f" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string86 = "fba4a73655b53fa1c5e219689b6173d9b4044d5205308b2cd8a18c9a03356ad9" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string87 = "ff03813f317942ddaa673985b0b84069cd74734ca4725f6ad89be3d2f95ffaf3" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string88 = /from\sdataplicity\.m2m\./ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string89 = "from lomond import WebSocket" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string90 = /https\:\/\/www\.dataplicity\.com\/.{0,100}\.py/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string91 = /m2m\.dataplicity\.com/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string92 = /support\@dataplicity\.com/ nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string93 = "USER_AGENT = 'Lomond/" nocase ascii wide
        // Description: enables connecting local systems to dataplicity cloud for remotely accessing them over the internet.
        // Reference: https://github.com/wildfoundry/dataplicity-agent
        $string94 = "wildfoundry/dataplicity-agent" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
