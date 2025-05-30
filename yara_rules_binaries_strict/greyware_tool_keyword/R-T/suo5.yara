rule suo5
{
    meta:
        description = "Detection patterns for the tool 'suo5' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "suo5"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string1 = /\/suo5\.git/ nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string2 = "/suo5/releases/" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string3 = "/suo5-darwin-amd64"
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string4 = "/suo5-darwin-arm64"
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string5 = /\/suo5\-gui\-darwin\.app\.zip/
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string6 = "/suo5-gui-linux"
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string7 = /\/suo5\-gui\-windows\.exe/ nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string8 = "/suo5-linux-amd64"
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string9 = "/suo5-linux-arm64"
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string10 = /\/suo5\-windows\-amd64\.exe/ nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string11 = /\:8070\/tomcat\/code\/suo5\.jsp/ nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string12 = /\\suo5\-gui\-darwin\.app\.zip/
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string13 = /\\suo5\-gui\-windows\.exe/ nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string14 = /\\suo5\-windows\-amd64\.exe/ nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string15 = "01a2453132babc0a02bf8a02a5dce58e75a6c4fe9bddbcc5659141fff047a13f" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string16 = "01d500c870f17df9745b6973a23efd33c05fe74680bb6bc1a0b5b74681480996" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string17 = "025c823bad7f5449606f1eebb3f486e723e6b41f3d809b59c0b4f2367ef14b41" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string18 = "0b1359c7b13b51d57bc917ca161f659550137e223ae0e317c3b4911fdfe59c7e" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string19 = "13dc14feae0ebb2947f49a047754133869fcefe72931f156232d109bc7fc9e03" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string20 = "14cb4039e1416fce558039dc2548cf185ae6e695479440d711992b238da6ef14" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string21 = "16ab17e1d91f55e133cea7ca0fcc38d0105b48e05975d86db76b556057e8ca8b" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string22 = "1792c809507a1b92737bd04b12cabaf28b36e7fc08ae524704317679ddb62844" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string23 = "17c6bc3e9a1d4086f3079f9bc140362f1278b8364777020b9ddddecf5fa7da94" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string24 = "17fd691675f7b9dcfe22195f729177613116448c4b5173e5f035bb4a3f67a361" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string25 = "19d9a81e3487b8a0624b927ca9a0703a716a383d41d61a22d4a1e20777713923" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string26 = "1a863b55ce99ee16151b756a7e9a26ac2b8d86e7bfa69ff99a6c0883ea25a6a6" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string27 = "1af99ff0796b156af3e46c20926f5aa5bd30e82821d7def568eae8a62ed44819" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string28 = "1b6c1c7541fe63d8b93d2ecdd39fa84fbabe464ad75fc822ccdea8b8bb0e3e56" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string29 = "1da8555f3513b39d821fc95a6a76ed4cd1b56ffcb30fc13c0eda59576ba5ebc4" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string30 = "1fd13e23e6e0959dc50d24207282f3873937f2e97c5f20205cef84d58dacc676" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string31 = "201281dccb6437ae62550434e78ff9cae3c2c19b7af8e9e55a3d1e89e32342d4" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string32 = "213021164bd91cb9caa8ea2ea283ff353349778d7e6e3c456a83224c11e55e3e" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string33 = "21f3a4015365376e1ba970afadcdf7ac5a13ba78feea2ed22f18de63872f2daa" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string34 = "2925973758d3d69cd2a8d4e6b504b367d4d664faecf422e49e614622d7cdb7d5" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string35 = "338e40f0af3c9e5afe576a70b19b005239fb97bd028891a1040ffd974927070f" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string36 = "37f9d73191d95d637f39fdc07f8ddead00f0093d3459a43b7b3f8e00ecf261af" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string37 = "3a4957346500bfcb99f671ffde44447a7d25da2f17e9ceefd68944beceb687b2" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string38 = "3b03a0738da391cc91566ea46c9b2a672546a0dcca12d3c6f2c10664c8c8e100" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string39 = "3c6bef218514ed8b5f4b07dac9005fa1f844750589c60d9c39e8ac2c2b6c6373" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string40 = "3d4704e3a7c0c5d4d1c0a272160e7d0944a017cea7cb08b367689f89516e4e6c" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string41 = "3dec7fe9898d3e4b31c6d61a1316390572bc6964128f14ad1595e4b252e10085" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string42 = "402b28519547fad2da345db67120a53369c50bfa90807fff186e3cdafad82de1" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string43 = "40b9410d301646531ac34beb1e22c3ac94742d21fd0d701b8b9b4fa04481e6fb" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string44 = "40dbbb8a09fa361ae16c91c374e435391b9104989241ba67389e2dc15d9e6034" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string45 = "44ce6895d6f3ed6945853af571d2ac24cb04a55ff4fa9425952181b840a028d2" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string46 = "45bc362420127dc6d00395da6c61d94036da73d110119965a52a8d83a5a88d31" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string47 = "4749831085b1c88950bff5d47d87409a05018597224f4149a22844163e6e1b75" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string48 = "482f372f9e30c5d31eb06c3ca96f4ae58df4aee2e714b1a613f21d99f478dfcf" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string49 = "48ca8e0be856ea824d915079a443f1aeca29ec805290d8605066f7ab59401abe" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string50 = "4f6a58fe1d179d2c9811e76d2cc469b5843bb5fddf9a5561b2b257810ae9416c" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string51 = "501555b3f33f3591deab2ab1b070502b45d63cf3c744661b7a32edc8f498e6ed" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string52 = "50d81308031ff4cd24705d157d6c5cf7d6e8afe7bec4bb2bbbadbd6699ad7a3f" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string53 = "52ca645cfcf80cfa3278dc9ec47105cd22995f39028082ba209a4ebcbb7844fe" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string54 = "54f11fb39afb17eeaa9c68482cf68e415ed87c3eb80f2fa9ead6431ddcf25bcc" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string55 = "55639c41a6ce5640182e63fbada1460f4d5eb77d7ca28cd03b5f81326a5ffd08" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string56 = "5571e24e95485116507bad42b229ca77a98da4ab7ce161d45f35ddacab12a3d6" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string57 = "5f43060bb9404309475297ee50dfe456863be25e3e4fc2e8c31300f471d3cc48" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string58 = "68a061deb112b2c02ba5f146b2dfc13ac8eafea91f15cb7f0f760bad4cc0c560" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string59 = "699c657acc47997abe868108294ab6625eae117242db51d6db5a715606a3e56e" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string60 = "6bf2e2c83556bad748940200d1ab7e6d10906a50062a0e5ac6ffe779b4449428" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string61 = "6c40ba5215fcdfbe5dabad38ef1202a1a95b5f31663f695bf404e8075674723e" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string62 = "6eaacd4b20f6cc94e884edde513bb561f7ce54e3388cb751caa2ffe6b781202e" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string63 = "70ff1ea046dbf3a51880965281a9d6a19b87e297303660346d36e7cb7969cd48" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string64 = "74c5657c473f13396e3200188c9958acd722072e26af9f6df55e623fb1bb15f8" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string65 = "7a755ed0f04fbb2ca6f802761b50036315ca25802a44a528287911dfaea2ed2a" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string66 = "7d0a1148c6f19ad8597975d65092e77a088de255c958e80403e33eb9826279ca" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string67 = "803441002d464ed753650ca0b322c96a939a7b9d073f9277367b51ea4a894cd5" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string68 = "80f47ef29cb32968c968bee785edf06e0cddc927cc016d7a735c7209300c813e" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string69 = "82b39dd75bda38dccb8f026507c583490b2f37dd299a2efde3c2d20b4a0143b0" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string70 = "86c8dd3f7083c274723554ad02410bbdaf990836ce6d6047cf3d759bc6761cf5" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string71 = "8807e7e0d5bf8197bc51533f3731adb29a89f1cb18355d3a3d59a88d73119464" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string72 = "8b1100e30d38c19fde571ff97412e66cdd2aef68c3699dcdb6b8416798db3cfb" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string73 = "940d75fcbce367cd600b46e2cdf9bae1481e6e977064996e11782b8da58fb106" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string74 = "94a3f1629cf89a01895fbace61e1533c0e7541b39a223581ec247e409ef4c329" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string75 = "99711b2b9f9da1f166dd69dc4542365edc60adefb2e8863bb8cae2bcd01ad15c" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string76 = "99fbf23aa2b2c348551cd4071c26e0612318fdf92f2699c6ca416368d43d9d21" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string77 = "9e032a335a7b50b69fec9d0b8ec9c64ae3d9986a6d78c79a013d97920809a282" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string78 = "9e3640e44bcdcb5ce5efb6fa63a306e63077427539ebe9a0c6d829808731c73f" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string79 = "a44b8353ce6c74595c2426c02d79495ffdd4b2472286b8622a901a430ed25251" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string80 = "abe2999a43f155a1af72ea97ef48c5c44a5e01fa3f6e1f34ac4c26c97ef17454" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string81 = "ac080f7b691d31d63adb6ec24db8b66953977752fec470326e5ee3143da86751" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string82 = "ac0d5f70d705c28c1b964693a633feb9eaffd5560f5ca564f96b0552208adf5a" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string83 = "aefc8f3e8e94a08015cc319e15a650a7b8c1c42ddb6a3f8e296196a0bec54e10" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string84 = "af836adb074c6174d4387d9fce5ed7e7bfaba965a21235974e409ab45c771c17" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string85 = "b2344770edbdf6582fc88f65541386d47a3d079b7ad316dda58004025ad447db" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string86 = "b830677a4de7462efd2cf843cd15ab382545f2243567ec1214f52bccccd168cd" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string87 = "b86ee9cb9b2d4f4c8dee5805a0ff07067cb31e8e7ede06159854314f8a3ff4b6" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string88 = "b8e1e263041bda37b87db45bd826c8dc4a81c0b60055df4f028ec4971cd55211" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string89 = "b957518edefbb9a18a66d6b3c298875e5a34818bb8b8924a58e53b6c863d906e" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string90 = "b9a7d9cee05f2f4132c71ad619dca8ce9d252ee2dabfee18a5ab552cab228fca" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string91 = "c2df4b64565ed88fc880fe54aee44a67b07804651be9f6b698b1e12784ef40ac" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string92 = "c317bfeaf967b44ca53f18c17c8b03ab7bb6d34c18383419451b28b084a91499" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string93 = "c730f343f26791992ca406e58e182e5185ba8a8bad1e2922c3f13f3f90be8a66" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string94 = "c7ad0c513a383487e712f2e5d61984f547071fa31e67c76d213647018e7251ca" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string95 = "c7dc584320f2e080de96e2889fa8139adfa1fe60aa2a670476a4bf6703fad2cb" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string96 = "cc29d56606b58a553757b5a24398b0d44c899eda409a6c9b55a4085e6b47aa8c" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string97 = "d172534380f802e8a74ef1ca3ae9bf0900d4c111cb79a9b6f4259a0bc8e744fa" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string98 = "d377c470516465e280c764e07ea16f50cc090082e0a7b888a0b76e42aa1f832c" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string99 = "d57bf88fbac385c407440291aeeffce75f46a1fa251efd5e3edac9d60f1e6984" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string100 = "d7ebe2b8352754e396c34d75c90e53ecd5fc15edb4492fc52eaba80a3ae991eb" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string101 = "db312dd2a5735817125933d4fcee8ebab756c9f402e35c687b5f967658628307" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string102 = "db6cf2fe1a2aef656873303d04ae8125bde61b11eccd551dc57969353a2c8141" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string103 = "e08ab2c0c649bc8d642c0587c57a19183467debabf900244f903e2adb96cf7a7" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string104 = "e1fa98aad857ad4bd52fb9aa42ba37b69aabfc0c1300da1d815b4e29c88d4270" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string105 = "e31cae3bfd37dedab001475b1571ddd186de0d4f01d4809b6e5b836e3a37c312" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string106 = "e3bbd11937075f6f6bb49c9118eea1579ef207967e89ef6b36fa91ebb81f729a" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string107 = "e6403e735f7ad321c83f64f4ecf5c3043dc167a4adb3163241003215b00ace9c" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string108 = "e64474e508d054c891d808e0702db18d3bf4304af5ae6ec2997c8aa59f4240e4" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string109 = "e7ad0cf754fa39b84ce801efadf247786a2d93e3126101562414da5bee4173e0" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string110 = "e8a2563e142a7165030209e28eddd16861dae29b09c5e9e6c047c2b7f3e2688d" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string111 = "eccdc25289e45340e203e27ff93a8c0e24b5fb6ba6317ccf1e0ad64296f395ce" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string112 = "ee5a09ea800c9dd9353a08a8b78e51cb781e211476b793cb6684cd95a18ed096" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string113 = "ee89364096c5e44a71f4a5b9a939026ae0184f350707e6e42d177ab8b8d7490b" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string114 = "f0a4507fc58b3c37a70bfd12bc2164fd323e9dcc06cafbc0b048f4b4891b9a49" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string115 = "f191225491a0fd4f9c1e2f0f89d7458aa06d9493e683d374a820e38b49e50e82" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string116 = "f2173450c0170fe8cbb61ebc77d8fc81fba08641e78a636e3cb0b943bca45eb1" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string117 = "f2f97e523f7f39ab24b30b0a046e59f5b5577452563fc615588dd53bd8c5097e" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string118 = "fa6fe18df0631bb7bd24068d6da47b6e4154ff339c3ae6b3c49ff1894c47f3f3" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string119 = "fad409fc082d2967d1871ea683c569c17fede1264abf8c9548b389725ca93ad8" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string120 = "fb2ea158fa75ca32d03110407cf7ef8f35e2191cff9f23464e783513d1561902" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string121 = "fca8b047b25fa5005da1c58c490d936e4744a25f54e9275efd2e3d084f779951" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string122 = "fd4a2bc256f098cde43e556226d86a211c5504ca3768366d40486677c7f2ad2f" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string123 = "fe3ff2cfe15f89b3357a4fa4648417f6b324ec1d27391b2e6c36e441e19340df" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string124 = "fe77ec34521fe3747717123a4504214f1bea87fb4772efbdb1b827094ae0cd03" nocase ascii wide
        // Description: http proxy tunneling tool
        // Reference: https://github.com/zema1/suo5
        $string125 = "zema1/suo5" nocase ascii wide
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
