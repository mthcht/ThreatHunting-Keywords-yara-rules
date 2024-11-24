rule restic
{
    meta:
        description = "Detection patterns for the tool 'restic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "restic"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string1 = /\s\-r\srclone\:.{0,100}\sinit/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string2 = /\srestic\.exe/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string3 = " restic/restic " nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string4 = /\/restic\-.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string5 = /\/restic\.exe/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string6 = "/restic/releases/download/" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string7 = /\/restic_.{0,100}_windows_amd64\.zip/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string8 = "/restic-master/" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string9 = /\\restic\-.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string10 = /\\restic\.exe/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string11 = /\\RESTIC_.{0,100}_WINDOWS_AMD64\.E\-FC5783E7\.pf/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string12 = /\\restic_.{0,100}_windows_amd64\.zip/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string13 = /\\restic\-completion\.ps1/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string14 = /\\restic\-master\\/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string15 = "031cf34eeafe09064a6b63bcf752093d742b89166e93924aa4dde13160f91301" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string16 = "03d40eba61566209bd634bde4492e7adcc34e8cfa94a6e2e72e0136c21534d8b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string17 = "03eec0acc40aaf248498e956528de90b8f7efc854ae8a0d0ccf5ed7377bd4e71" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string18 = "03f1fdbd7837c1934ce54d05f2ec947c62a45e93e68b7cf7d612310e095a1626" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string19 = "0416febc1e9447269a9b414f0bbfe0172453fb5d03f0a756eca799060b1db6d5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string20 = "0440615136eecfa56e9844e37679738622563c126c9cafb96433cec4ba11699a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string21 = "0440b6c1c17b58563c729fa133896199406f29356329ca5d048e4d9dcbf7d6fe" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string22 = "054cb9f42c4aca898ef078ddb7b138517c6f9f80225f9c7204f6ee00b9b93134" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string23 = "0550e9375d01e30924e8e551ddab23e2422afdb978348b73e51f912cff544633" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string24 = "066ab67daf36067b99c2c0346d95f69372e5b38a0917396d2470713684e965f4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string25 = "067fbc0cf0eee4afdc361e12bd03b266e80e85a726647e53709854ec142dd94e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string26 = "06bf3107ccb34b3c144d07ed52a0f39ae0f011d3af0cb951b2927ae2350c4631" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string27 = "076a40a96cbd1931e456facffc9f1f3bc863a5b4f9e2eb95749952e8c03400af" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string28 = "07cb932052b68c612875bca687f2a223359c2df6aaf6356710253fcda2b0fb5a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string29 = "0820eee2fc73291dffd3794511099582b2b5dc0e5e112fea75100e64834f95f4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string30 = "084a42ddb25d1cdec5b607e7ef814c6feb7e644fe4d7648b28c590c705d1abf1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string31 = "084e97e9ebab79b4fe01d48f70c81cfbdc45d811265f3987eb7c322be34e39d0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string32 = "086848f2d4683ed2d581b584648d5c9c1bfe9ff61b85005c8a6477079f58b95d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string33 = "08bb9b6592f50f08dcdd69a834028520f03e3186e530e69135f91ffc71d63e1a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string34 = "08cd75e56a67161e9b16885816f04b2bf1fb5b03bc0677b0ccf3812781c1a2ec" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string35 = "08eee3c5dfdc940f19deba942d5bd9a9e824cdfd1212db7eead5644f556f7a9e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string36 = "08ef26797923f93bb5a395f7d4e4bf9bddab731f0c38c29cdd843848f7b3bc89" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string37 = "0900453b3118e8907fd19a1bb4b56d29c3f09b20d1eaccc773e888f80761d065" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string38 = "091518fa5ffd54b71b90eaefdf9d8d05fbf0da1b5585d39ec9e202bf9c448a47" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string39 = "0915925d325e078508375c4ffbd4570c392c13640977a05e19db330a75ab510a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string40 = "0a8ce786d48460aa1d4a75624c19262482df822fc36906461d602bb9451b2d3a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string41 = "0ac18d8f1ea7306f3d76df0d034de4b2ae839027e88a86073f4745cfa181af2c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string42 = "0af3ca934eb27efcb04923f478a90528eddc5ad8ffc4c0b183d83896383eaffe" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string43 = "0b2bc7f3b6b1117924d30ce00aba145b572893f69289c1e8da24ab545ffc16eb" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string44 = "0b6ea556073812f430482992e60bffc80ca1134bd83b05a0575f577498833c86" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string45 = "0bcf557bb9fdac75b80c93f575ff2810e7c7c30b9fbf895f424c046d43c7cc68" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string46 = "0bec24bf1d313b22de9c879bf3803256f945be419f23db4e58fdb73c3f15ec31" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string47 = "0c19de7f525b4f40bf35347c9834564e48cdfdf1b64972d0aef9e548d29960dd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string48 = "0c209fa7735b7a129d52fe5defb41289d878233480d2660803045811ba40a62f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string49 = "0cf697c88404b180d6d6ff2e7d2c27b2fcb9536da6dbdf15ad4d320af7e8f17c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string50 = "0e0f4b20b92d63623bd0abfc7a233a26a66834efb8a36d67c9dd14fdd973822d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string51 = "0e8ddd8fb30e6bddc6204052e06957a39a85536f5cb89e1c813d9eff3d3977cf" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string52 = "0e95898310ad782ee54b42098c6b43b7c3e3b58a44e7f841d6533e441f011164" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string53 = "0ebaf56b7fe452a53e760b44bfa69331bb6b03dda5b538b69a5b8642e12a8b41" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string54 = "0fc75aed0d84a67a75a937e4543fe2c324dc2e4422ea8d0431ec63ac15cbde16" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string55 = "10b3f5491e54c82b421980e848542f8f589ad6635f83fb2d89d9996cb37ac9c7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string56 = "11b9976846f11e0d163abe45ab025ef7b26ce86a94dda613bfd8e4b51eb63bb6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string57 = "11d6ee35ec73058dae73d31d9cd17fe79661090abeb034ec6e13e3c69a4e7088" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string58 = "120dca6c0da5706f7868b653f74eedac4e218b3d155a1963d66302d9eb363511" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string59 = "1219aed961e396fb1be1c2a86218cc72de87bcc4461f22f9d87cd1fccf7fc30c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string60 = "124438413ba085530b9a0ec928dbcec411a401e0127940bd8d439072e054e2d2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string61 = "12d51bd60e658ef48f066fb5c872382fe0ad60a7665985e25895651c78019d2d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string62 = "1386e1efbcc9585fdc22c8a1f453b7da8b0f97b1a0e339cef1d26753bc368096" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string63 = "15229ecd98cf8496d02e8a4918a27099d2e8202e559e5d2e3e92b4cdc4bcc5ec" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string64 = "160fbd38f7e626afc5f99a239776423629bd4b1e6cb9891c7ecf1a08acae06a4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string65 = "1636a30b0c9e7c1a9411d30696df2a2a62666ae30f8cdf14a0f71d3715c897c0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string66 = "1665a0292194daca49b91f61498f048d3099193c562c81f60eb311aabec54313" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string67 = "16935a0807abc635a6ad76b85b95fe703beaf188e5d3f27404b9e699e87c4f07" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string68 = "1719136d3545bf0539b4e9c323e90e2389749d7f1eee98803bae39fa318af4f5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string69 = "1815747d94340ba15a0443856675aa23d778c743a9cb8478b0025a40ab5add68" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string70 = "1847da329255b121b83e0da08c255017c9fcf05bf0bc99fea3714430e5d383eb" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string71 = "18ac281a3d3d2df65755abadf75bbb551cf62d5613f5821ad0e08c9088978f93" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string72 = "18db38d87241a38cb3b44b1b2e320009fa5e129804a7970c71ea4399fc4dec27" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string73 = "1930f4934eb50f2aca7341a4fd5cb7053c39a76fd38d185551d2b3a60283bfdf" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string74 = "193edf6cc11c84106a634bd990feda1d50c24bb99e405f1eff6bf74b965dcadd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string75 = "19b77a9c4b75bd82b5ed2b13f6119b5f5dd8fadbec880b1c9897f25c3beb8a71" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string76 = "19cc16baa9f9a85123f627bc2ca7eff0f5d901a4674ea96b4ebb21df2183c8b5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string77 = "1a367846c52078e39113a1ff7d1d5615637a06c19a63215570e4d058c3faf329" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string78 = "1a56d77d702056356afad246655a1974c5df127163542753f0fcede98a250045" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string79 = "1a5c1d2a3b17aa381c318b3f3919f7cfc4cd430c3a2c3053ba055fb4ccf38c97" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string80 = "1ad8a76a9f966da5f7a319c49a6db071a60ebaa24d69e6d86d53d6f2bcaf11ed" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string81 = "1ba52a6f7c12d32fd2a9d21503bcbed51533a07f24c6aa94f82b7d58eb87841d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string82 = "1c07a12c276062d9c70006a6e7377b7297d510ce78d52f9e62e3848ad585a822" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string83 = "1cc8655fa99f06e787871a9f8b5ceec283c856fa341a5b38824a0ca89420b0fe" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string84 = "1d347f8bda31bc7dfce658a6b17459f32b7f8d2b76708d30bc5ee7cd3e9eab5b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string85 = "1e0e0d1e7388beaa2a892c057759fdfe6a4fe915f9518c73068761f8d6d7619d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string86 = "1e93b311f27b676be80419ae9ada6e3e599fb38e204bf27ecd14320e1b4dc1c3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string87 = "1e9aca80c4f4e263c72a83d4333a9dac0e24b24e1fe11a8dc1d9b38d77883705" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string88 = "1eab0f66e1cf84017ad8aac6358d7bd50fef62477281b9492ccf772be20caf3c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string89 = "1ed7632518a86fa468f5823d6da4826d1787845cc0969a46da110c98139a3db4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string90 = "1ede16b360710fe5f9471474979f8cca5ad6e2005bd0088c3d54a3272677fb4d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string91 = "1f9d03503d8756311b7904e99aee3460f1ace427aad88f6dcba6a97a9c5a8171" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string92 = "1fb74dc72e792566b0caf2c596b7d6e655caaa678b8cc0c1f6975427d64746e0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string93 = "1fde906bc848a16734929e3d27c2223ab4e5be688b497cdcd8a0c4849931769b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string94 = "20a8ce365cfc6c0fd2dd88d2e68eaeaff42970f3e1ff34bb6ff8b6d6ebeaa58f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string95 = "20cd35745fdb39b8ced14a6351b96ddd0c5eb248b7fb5a4ef7a3b6a7ea9bdb9b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string96 = "20d323af78ca61c911fc9558d3621307e6a5beaaa635346bce8b5a6211c6a8f3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string97 = "20d91064fbae6a009aa552a11389523f977c8bf49c1bfbd2ce5f7e33609beb08" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string98 = "2104df5140488fec740f2f225439d14e11343dc6865f7220cb407d83b0089068" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string99 = "21420350ef2f6884e9ef0d21c1ef82867f992e2b809b4ceb8292a8ab8dd02d3a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string100 = "21d614435d3d6e1e26ed3a4654232d1c1350a846cff9f620dc9e76944fd516b3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string101 = "2267fd0ff2e6387c44e736eccceba289a2b273fc3ccec5786af82415a1c9fa5b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string102 = "22725b8da1f7759e83424dbef84e89614767804a22e49feaba0013587f21208a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string103 = "22cc11da0c91690bdea21d873ea341d8d31f44ba32602a2e3c40809b334cdf19" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string104 = "239f075f17c926b724d3128ce8368fa8bb7671ff89524e445312ce115c8f727b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string105 = "23c553049bbad7d777cd3b3d6065efa2edc2be13fd5eb1af15b43b6bfaf70bac" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string106 = "23d83edaf39639ad843dc07a853215fae94265e590e6242951df5e6441dac3c4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string107 = "23e12a93521ba83f5a5d238030dec3cc47788a47e252eb06335b613695fe9d34" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string108 = "24125fd40e20be4c607e7ff58bdce302473460f5d31cba9172cdff2946878d1f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string109 = "2467af3d886f3bd9838846f40134537336671a7ff34370145b233a3f9f265beb" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string110 = "24c7ca3fe6905b3a493a67237ff081ba9e11abfb27dcb73f18d0a4595926c35d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string111 = "2536aad7d213c553a2aa3b6c6d3402bb9adf2c7624bf004a14a19751b24ce80e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string112 = "2655b585e686b5d6c36d1be640d873fa15a53a86c46e2ceb5fb00eb562c428bb" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string113 = "265b1f417eafc654b5e789ce044de99635c542f2490708835b95669ed4fa79b1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string114 = "26850257bff3d64408313c3f6750f9d3880a3729568bd78a40b1d75ca3d4cea1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string115 = "26c4c55363fc2a15122a97384a44c73fedf14b832721a0b4a86dc361468e7547" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string116 = "26d3bc4ed714c268ba2fc84034d54cbeabc230ab2e498e119a2243cefd9a93f3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string117 = "27e14febe4ff06aa6a51e01d239d2d4e3af88407d59ffd8feffe54247309b50a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string118 = "27e5b4ad48de612df3a28a8ca9d0b4015b6d24e959056d66367ec53246899e44" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string119 = "286cf8ac789b4752825dd6098cae26394b8803b99cd2d4cdb2153d9ef73f49c4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string120 = "287f321328930e9fcb910c216b530c9e6fc1badefa4797779369b455f16f32a6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string121 = "288bac8790bd8f10894a70733ed78bb7afc098d55b41fe6dc4e044f80ef5612e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string122 = "297ce47c277bcb97df904493b594d6a6e2ddf8c304d572214b53089f0eb55d42" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string123 = "29b4b4f15c9b4d74a44576c80e5cbc3cc4644bf55a7c2ba29c73b3d9e4f24356" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string124 = "29bc472e151a34cdc5dc5229a27ad5377d091df53500e7ad0022d663a4b9d3a7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string125 = "29d8abba60342eb0cdac692d050c95feab0aa980a2c8779fa4584f97b8196f26" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string126 = "2a782979f8065e162c99cbba25bd80ace68c743192703e7b2d4cc6ca0acf5625" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string127 = "2b3ac83c63ff25980360d246ecf86132dd1cfe3416957f145847c80494750846" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string128 = "2c279e408c09fe9be4dad0a1f688b228a8e1948ffca2ab04431fbc53c7877c19" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string129 = "2c50ac9cc40a98a74c88cc3ee248e1550464009866d44356f1db0c3cc6433903" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string130 = "2e7585939693c87bbb35a55bdce13253747dcbab8ec4eab0e10b342ffe9148a4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string131 = "2e8a57f0d1d2b90d67253d1287159dc467bdb7f3b385be2db39e7213b44672be" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string132 = "2ec2fe545387d5c91845130aad884ee212fdf3374690dfceaa422ad7545ea7a0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string133 = "2ee2106e77f6c197ed167c064e4cd24cdca2a824c3d37805e201c9eed6c2f3a2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string134 = "2f2d847e45c63766134c300e0fffec4acc13141b7fa23e77485e14592a933b4b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string135 = "2f46c381b4f2964068e256f85f11cacdda75601cf0ef5069e08b3ed91c2f7c9c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string136 = "2f5301deb35d5d2bd0639dc172247df8b33dddb04034addf3d42c9bf2a9bacc6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string137 = "2f81bffd408e9f57f31d9c91dd59473bbd57dd27d6e90eb582db2365bf3faf1b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string138 = "3000e68455aa68222a46c10161ffdd921929fb2a14d5093cb4f64a569737c50c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string139 = "303d31423ac6fc64a185886ae639a9f85126cc39e4bc0c58ca1320a06cd2ac2c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string140 = "30c290f0f1d6bb3553604c337d4a85cd38b7b5c8dc738386cda54ff740a9bb1f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string141 = "311a9c3ba000730148d78ed854f7235a3d05530ccfff5a868cb6357ec93b83c3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string142 = "31339090e3e8a044d014b9341c025cf59bf7bc133ae267bc5acdea5ac07837a9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string143 = "32273bc91ff97d985a6a1e97037b9e3814f87db6b1751201e94594ee49bdb808" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string144 = "327426b8391497fc97c5d0fd0ccc9107cb3e2c2c2c25c5c8d3d7bf138ebfebe8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string145 = "328dac26bf8b47c20c4525f0c4c21f17857c1606355dc42362d37be5d3d4c95b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string146 = "32de5f522092e4dd545d064e7bc2db58244200af33559bc7190d18c93edbc397" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string147 = "3365e35e064a5dc3720c596dbc64c56f8cf6d079b30085f2ff7a148e7ebc6e55" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string148 = "349eb981d2d5b1f4b16127d6a0c07929ff6851d15f816a9d09ff71154743a9e1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string149 = "34f4d439f01d02cf9b4d3f840375af6f2ef130e70730cf45f3989f9349c65326" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string150 = "35396671b32a78b457168a6413a2e0c7818e8ae740905eb273c0198f051e930f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string151 = "359d3b8e555a9952f2b98c81ee3dbec8dc441e12789c436ca564762aaacec095" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string152 = "35e6e7e783afa5c5397acfde3b9237a5b1ace0cf4d0d3bf3f2d77ff601cd5157" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string153 = "3631e3c3833c84ba71f22ea3df20381676abc7476a7f6d14424d9abfada91414" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string154 = "36b87e150926457e25e95098f2f386f63f43c2aee5d30275582e6ba044de4003" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string155 = "370485cb64eca360249e7232e2b0400a5d1d0c937f91e8bcc7b1d545eb23a162" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string156 = "37dbd859160bbb6d1b95e9f4a5c498c8df386db510950875c70328f688cb4e5d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string157 = "38022b590f11207be34e2eb14ab67b85774ee27d3f9903460173f1d1b77db6de" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string158 = "391432015104d8987eb9bce325017b71f6343d8ca970c94b81374aca7aa5035f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string159 = "394a6568c9b0e5de222256451e18de4e5b9379b058cb9fb3b04ae66c45354e16" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string160 = "3990b68a8b0de116612ecfe7b85690659aad1ef779c606b0b6d928c402f3d821" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string161 = "39b615a36a5082209a049cce188f0654c6435f0bc4178b7663672334594f10fe" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string162 = "3a379eedcb90ad0ec60a24c89f9892eb7a12ddb8a28045e432fc2c43e7faa186" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string163 = "3a7686526b309fdfe287a88e49efb56bc9dfe5c5e02e78b4f09a942cfb2de7d0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string164 = "3b5f8f9ea98033c46c65edd222a676b5844186114ada1d91a56c58b0abcd0612" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string165 = "3c63b475a56cfb3569784a78f7e712843d096779fa5b1984bdef0cebb2c31437" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string166 = "3c748064aa6d61727905c9ecd3be96b282448ae9c13368f836834ab0b49ad6e1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string167 = "3c7522dd19a1d8341e33c910afe1a84d8b9dda03de6d2cddbfb145f401e56a33" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string168 = "3c882962fc07f611a6147ada99c9909770d3e519210fd483cde9609c6bdd900c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string169 = "3cc1f7c3389f4f9d9f67dc0c0bf9a12d1ef413edc6b3c770f5faa5cd6e275dfe" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string170 = "3d4d43c169a9e28ea76303b1e8b810f0dcede7478555fdaa8959971ad499e324" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string171 = "3e8a768889dd85d952fc7160d196c68866c9155383b0347c4049d079c8ae2cdd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string172 = "3e9460a86fa16e9273c3a09f4cefccfd6e9a27ece4836fe2c3409593ba24c21f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string173 = "3f01015707ba586af211445b24c078088e888e1d496776d2290c85ced4c0fc8d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string174 = "3f031af58b8b614eafe0fbefb338542b7b04f878853fa9f62394a00923375735" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string175 = "3f3ebac013334cb9fd5d1f4556c67ed3e663338b72b48dce0ec0ee774690a8c5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string176 = "3fe6bb27a84dc5b565f2a31d2297497df75af2da88390e0b893ef90cae605a23" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string177 = "3fee12f2bf405e28cc35e8fe8379d9d73345a79ee8347f4928701158495bb266" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string178 = "40862cc6300a8460151fc4adda2d95bfc405f581919c0732ef654cf22a99584f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string179 = "40d9fe8c9f191ab5d0f3e172eadac4fb3aef7a698b895a22ce81102b0a0f270a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string180 = "411e557dd4765d49299e45c2c6700f436da20c1e455dffa36406bd841b5863c9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string181 = "41cc6ad3ac5e99ee088011f628fafcb4fa1e4d3846be2333e5c2a3f6143cd0c1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string182 = "41d0b1d19e7427cca350e9079cd4c52145d6c1bc4c9f89d1b9b7328ceeaa9d26" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string183 = "41d47f100f61c503c462f53069e5c2aaad4dafec461e56b85b1de7730e4f9c4d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string184 = "41dcb500cafd238bee5efab4de53eaca0c22bb5d504c4ef5e2672b91c341c5e4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string185 = "421df18208f862250939213750c7573b4880fc0583a46d757e039e615bc60877" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string186 = "4231518d2e5ed5fa9f486f6259367e6cf82e850b19842e8c4f801bba4ed781be" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string187 = "4241fd63136c5f19a197d232b8be95e88b06dd9d2052c950404dd6567d922ab7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string188 = "4255a5579488169942100c59340c13cd7c7918ee2ef75efee8f237a7996f2c7f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string189 = "42697577979dbc80eb0f7506f4e515fcb22ef731e4199c33d98c450ed73967ac" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string190 = "426eb5437d5f204ca5788afd05e3f8e5ead876235bb6182b06a03c353bdaf8c7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string191 = "42a758228141c7215bd913352516e8ab1e02c9f786e1f4076f7c1d245e9815b0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string192 = "42ab238bd96334665442e896141ba5e9aca31b2a27d672f7a6f111be1f825611" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string193 = "434d77b8079a27f303d30758ad99152abf3102095b6bb3573c1de307f1ab6345" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string194 = "43836fc05af4c552cb500cdc87a6ca06a6fb0f6b8f179171f1a971aee0a4d6f7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string195 = "43f13d70c3f9912a1ff1eac831c2c728b3864b332974fb57b0a33a4bba85487c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string196 = "44ce3367b0b413ad48757de8e2a1f4e2c30137e7cdc77db64906f3eb7087b78f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string197 = "452b0b0626412b439f83ad72cce7f280434fc690f4b4851417a759fc4d60392b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string198 = "457676a918bae4371b312fcf6308578078d5c944758ff808307d9b416a98f68f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string199 = "459f93b1384a4a734787f259252959e88baaea1cb7b790a4f1779c4163efb1ed" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string200 = "466ccb2dcccfff96a199d4f84c05a0e80e932ba44d0f4de4b851f1b8180a7a4c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string201 = "46d932ff5e5ca781fb01d313a56cf4087f27250fbdc0d7cb56fa958476bb8af8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string202 = "46e430adf1e95bd73f253c42f270b1e2b209457cad4e45edae59ff6e87a27069" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string203 = "4743ea0bcead6c3d7e8444711f627c0ee495cb651d3490960ec8b6fb742ae9db" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string204 = "47740183a3e2ffdb4acc17a97456de9406f158ec4c964d9d6627fd6711032a86" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string205 = "47ab8cf4c8a99b270634aae6b5bdbf49ba75aedc09ca04e0fd43a7be9108c27a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string206 = "47c3345b1bb58e7f984c41831bbc845f1c61a6add5cbf5b3a52a691c78e83c9a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string207 = "489b3873fd79e99feae45e5953ccca3fd21a84eb68a99654ca0a6ac1b2dcd255" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string208 = "492387572bb2c4de904fa400636e05492e7200b331335743d46f2f2874150162" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string209 = "49a093e97e5091456452d7e8edc9450cb0028ba777b62711b209b9db12317cdd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string210 = "49b63459ce22867bee13f2589aba38a51ed5bc728fd6f38f9ab107c7a4f00471" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string211 = "4acda13c308d3fd2b892ddf6fe210b8438c7a97abe88797315d06600fcfcbcc6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string212 = "4ad8bca8939396f8a99252e096891b064472e3abd9b8fdd1b7c2e4c80cc74348" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string213 = "4af2dc16619d3a9da05be6220a9b160433d5b0fc37bd6b679afbdd6e73a79a4f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string214 = "4b2335364a62f3268581e6343b3b9243fa89ef6a48ca9b24ea2db1a949e91156" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string215 = "4b7c2e0e6e2491b55ca2bfc8d7198fa7e750afb8a5e779fa50623fa718fd7827" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string216 = "4bcce7c204dc4ce408bfb2a127ff17294b845d435d6f5f3cb3ab6064d9d3188d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string217 = "4c908414d885dbe8b105b4c794931bcaf649a8184e1addda4785cef8307bc3e7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string218 = "4d9ec99ceec71df88f47c5ebae5fdd15474f7d36e9685a655830c2fc89ad9153" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string219 = "4e55db9ef3e258914860532610cc37db12e2f875f9bd8fd5b789c4a55f7b4f6c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string220 = "4e9929b68f2e9f3df50e4b320ee85357134efde38986d25983b8fcf50e19cd22" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string221 = "4eb7ebda84217bc575fff510a5534f5750772915d6efa435a9ce49ef5eb0b075" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string222 = "4ef3458f9635baf5cfd25a793486b612df7f4904c91eb2e4558d9713fcd34912" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string223 = "4f3e5adb0523a6811d21570838c9f061b7c9bb01264be518d0ed55039ac42547" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string224 = "4f8be171615906969f1393b450924f0afe3458ff88f7fb8be89f5c02837b4026" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string225 = "50362f6c4c2d91cf0edc750c578b73605fdbb79443874110cc0a64913553f76b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string226 = "50a8e58ad1cda3eaabbd812d064b7cb40e7119b6c4838ef5c1c74b8f6db8a5cc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string227 = "5129b1b4b402350d6a7ff85b511dc2c8c94148e8fdb25d57c368d47cbe5d6703" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string228 = "514d0711317427f45d3ca23e66cf66e9f98caef660314d843f59b38511e94a2c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string229 = "527ddd722d4629f835321d6b8cb25f28d4b55fb7b7e946e95c1e2098b88f86ef" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string230 = "52aca841486eaf4fe6422b059aa05bbf20db94b957de1d3fca019ed2af8192b7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string231 = "53774723cd9aa6a4a815ad002dd8be8535611237463240767ef3821f0d9e14b4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string232 = "53b7392e1f6973680579aa054458531886ef6d359868bcb2a4a52f7ffa5cf8f3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string233 = "53ce7b5352a21cee0659ff9fbe71cd553cce35e1f72cb5db10975263fccebd47" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string234 = "53d0b11932ca6402d75e8ace78625dac6599573d8e783001faf161dc8bccf063" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string235 = "53f3f97e369c874277a38fec36f2d533a865ad22c4ff8f06e4335f682c36b65a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string236 = "542fd8635fa9784837b4adc0baf96ec514ed347c30603db9bc953ecce68399e4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string237 = "57384f36febc695b32b0fd2910643ddaad6770898cf63a9f97a2f76e9faed5a8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string238 = "574aeb6cb673aa96cab6fa82656126f1ece4079edf89f68de09a3fce708ad47e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string239 = "57556703267587c0017816c99be4a8a9b7ddead80a45dfce31b2fdab2a0304a5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string240 = "575a6a7a4c23274aefb4eff8c0614036cc1999f108142741ce5296e4ce00811b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string241 = "5785f21245163c072e0f3acc39f86e5d105bf54c0245bbfcba5d2d21d1d6f301" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string242 = "57b5c5dbb54b9438aec465b9112ff4936876172c09f35746ddaa8792b52eb347" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string243 = "58170b311be68a8149d51edce1c837bc1feb49b0f6b95b64a0bf76c2a7820a52" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string244 = "581f25669bf62fbf90100987fc62d36c31e6781f1dd89e155e45e79c17fda0bf" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string245 = "5828751f5c11d3f77fbae66a616adf3a46fe1e09c130d282830597718769b869" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string246 = "58a1d3e8d51cc32760153418672a3a0a7d81b2996895fa533614842ca0a75c98" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string247 = "5ad984e4bc9cf2b67a414f99c48b2f5621b12efaa1c838e4a6a13a7333641dc7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string248 = "5b46612254dcaec09a6f7ddae70e116f77c0f87ac7988dc379b34d0fd4bbc4c4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string249 = "5b94b821a76615c0557b5c98c66253e72f86a1b1ed18c908cf370b603fa10c3f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string250 = "5be16e35f6b1f8339af50531e3c165d3287f2bba9d1ad27a9c4e601364a0eb5c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string251 = "5bf8796898cefcaced122d5188653d74ccf4412a3686f84cbcc312ebc1bd74ea" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string252 = "5bfc3639ab04d2456ed2e69be163a1b0734f14518b46ab711bac4c23e74585b0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string253 = "5c0f7d058401e664d0c6f244a0c928a8cc4dcf4db038896118f7b94e35cc6c46" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string254 = "5d86a4eb9a7178bb95ce83bf687929a433c9a4aaa2ba92b6330b393709acf745" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string255 = "5dc863dba915a904465b9da951175ecc957fe3e016d1a026b3688a5c1cfadd80" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string256 = "5dd33ccba1c352f77d7578c5360c6f913092ea2f43ecbf919baf95b563902e2d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string257 = "5e4ebdeae037d0b3320d9793e91c6fe838a8436047ba030d54a13937a0c195a6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string258 = "5e7f65847b489875621d1732cfe4e2c46b7ddf3b0ced8e4d5b4e56a4a4a3f2f8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string259 = "5ff6757d8544719b70bfa25c08f13781421e260b60c9351c88a4898be159dff8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string260 = "60376b01b334a0cee3a59016f44dde8b336de2b6aa44f1e6e403d307990c47a0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string261 = "608b6b396eed970d75d8030e8f54c5aa06ba7b2b368ddcd80f114da24a62f6de" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string262 = "612691d7e5100f1714fd4ce7c2ecee2c5b0447d68b480278d54ec58f6c7e2e29" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string263 = "613428c4c54093ada2ee1b5c9fe1cccf8bf781bc07fc64071d0e21e55f99a0c1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string264 = "62655adaad7e6118fde3fff73cfc07f73ecd898900b9518c3b7aec5b2ac7623e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string265 = "626ca456089857683c1ab8a5e3eda282837f7ed466ecf1a3c2cdd30e1b309c35" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string266 = "63d13d53834ea8aa4d461f0bfe32a89c70ec47e239b91f029ed10bd88b8f4b80" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string267 = "63f982006a02f5dd1b521e16cf203e42bf9a479deab3e89fa88b99e49cb03364" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string268 = "6410bf4446b371c8cc9dab16e0cdc1d0e5f21cfd3750a3a20f4c07c36befd5bc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string269 = "66ee25c76d430eea6f787983fe0e79368304ddc69494a4876b012bc3932b1db3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string270 = "67003a49d703431238d30117af78874ef72453ba883cc8d2f03e1a4227da54f9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string271 = "67392f0cdf1ea5443b9f625eff4eb55e3630fec77b16e35b01c5b2214023f331" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string272 = "680085ce3348940cb67940e3ca7da4ae409ab3169c99592052760ffaf374f9a0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string273 = "68200563fb40d6ba3b6f744c919867bfc6fd6106b6317e55853d37f797b783b5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string274 = "683b19a505756b7dc99eca09caf00cd546d474405f08151daef687c890919027" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string275 = "6880a6b34d856513873c439fc59d8c51c392fe360d5e69577d4e707d6ef77c02" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string276 = "692e70ade358ad4fe19f0cd5fbaf21c3830d0f23c3d4e491a043f6cbc1b5cf59" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string277 = "6936a522d7d0afd5955bc461cdc63d228aaf33d6cbeb7096e26d7ee90010d954" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string278 = "6a794fbb4e3db6e878ee213bfa6b5307136c074fd2214ca242c6ec4609f59785" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string279 = "6b2fc43f794182788aaa8dae50f1f731c33c5126558e621d693c18455aae92cc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string280 = "6b381ea3ed5d0925032ff8d98fe5c443668699983ba7e7b20fddd2b34b5796f0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string281 = "6caae495c78cfaf80bef557903f997db566a5cf3ea08c03d6f09e2c30a6d6d0a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string282 = "6cc2585e1b00bf07cd02b4ee08fb51e88cba155f4a10f753142eb9cc1fcccbc8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string283 = "6cecfa1b5cfba371a6a576e213eeb90f5ea82a91f94fb520cf9160a6526e0ac8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string284 = "6d45c62ffaf587bb28e8c24ce0b29187df9589cce0daa6a2ccc02605a3a4f529" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string285 = "6d795a5f052b3a8cb8e7571629da14f00e92035b7174eb20e32fd1440f68aaff" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string286 = "6d94fd795439afe13c95030b1b33a606beae24cab986395e374142021c59a7fa" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string287 = "6df9f806f4cb4001e3722196bfe629c48c2dd39078b33e96db139823db1236e1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string288 = "6dfa9158c5e57aab361fe9b554369024c16671a134eb34b1604d0e170e184f57" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string289 = "6ee05f1a72395ef7d41538ef5cc84395d5a168d13e3054a329f0d9f593f80f6d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string290 = "6f252952b482ffac286cfec43774b6f510ad7f47eb7332ce8bbddc1400a91ec3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string291 = "6f93ebfce80642e697c1de729ccf6ac3d0d3c7171d4d53e9c69eeaf3417f0d77" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string292 = "6f9d22dde53839cfc4a035c019f2e55fa6a7e7e1ac308060ec312b70e6272611" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string293 = "6fab3fa836659c85b97e7a8e514bdbb8d4df186600212a7b5c36cafff7942e38" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string294 = "6fae4e720a4f9d3d8b9b635ac161596ab4dce24168dabd75e41ccead6915a454" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string295 = "702e44943daae9c094858ed1a8a50e427264a1967535cad0362ce80fdf5acc92" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string296 = "713eedbc3a86409bb621d853b9fb157c2abe789a9b696796ca0e887e610e8295" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string297 = "718883f3de3684d2fb9c8c905de422a5cefac2bc7dac2b0cad1698be61d54cb9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string298 = "72c04c3a683943559166a4ef21e7e35670531d6fdf28d3482298b75d5f736718" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string299 = "72ce6357beb322ad185e5aec9247665babe206519ec7b0b741b285fdb60375f8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string300 = "72fbdbca48fabbc84dfe551bdd3bc2d8d8b96b30ca7a2a71344c4d0878d91d99" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string301 = "733c94230677c98424402523a308d03893948c0c89be9920f3ffae73ecbdbc71" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string302 = "73cf434ec93e2e20aa3d593dc5eacb221a71d5ae0943ca59bdffedeaf238a9c6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string303 = "743d40286b6e5d2f630e7f6f2e2609ae4b1d99c455c949677549e63495f6f65a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string304 = "7492c254c277a271e909f2799447aeab7d753a79d0d231b2246cc2c4a2f92738" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string305 = "754754c196b3601f2c29758c94000f208a880d45f9b1cc3164123962c97f4ad7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string306 = "759769fb5f4ddb821039eb7aa68632b0f24625e93fd1298ac30474b6343467db" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string307 = "75e67a2bd8883d61ee6d62b37ffea24c92ee446d6443a67b17bbfbf449d17e1b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string308 = "76a2c3a4f3a39d91c6b42e2990efc64d878a6b5733ff1b14782e4fcdd50fca70" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string309 = "76da4679b37e969c96e2a243e8b4e94a622be8cf28261e722b7f7a70874a3691" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string310 = "772acdb9d5502a67fabe618d3ebf734879f4f5aaf3249aaea40c2d6d0c81d117" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string311 = "772bec520912784af836fb89dee9a61763aa3c1c6340753fe1dbbc9a2cfb9ea7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string312 = "77310426d3e2e159f1ef2c8d498f17dc47cbeae310451377a2857f3ce9cd73c0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string313 = "774279ce55ca7b8136f36328ce57a884af2880a8f2097160fd44b646aa8e1429" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string314 = "7788d7ab1b6b9e57d30766caaacac880553dc869c3c346c194e5bc83d368a1ba" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string315 = "78312276c42ff12162e5afaf6de8586d432022c8bc7551366471b8812703be7e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string316 = "783cde05218d88146f9401491cc0431917cb479009f75c3af1e14c4e42bf6a84" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string317 = "78abad9b589f303f6d9c129ed5ebfe240fbdbdaa5bb0ffec43dacb2991bd526a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string318 = "78cdd8994908ebe7923188395734bb3cdc9101477e4163c67e7cc3b8fd3b4bd6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string319 = "78fb147d286d223da111ca67f5e0e2532026e3b24a5c513a109c026ff6f025bd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string320 = "79ade448ca0b6f8b378fa067b60e199a4b5bcbe779397beb1e046f239f60f7e6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string321 = "79f3f7872f14c334104740fc6199ab8eba2a91ddf6f5d2dcbaf6b58ab95362d5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string322 = "7a0e3f15d12453d6661ff40e068bfee6df470b531e2a5c434a7f62752fc5ca8b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string323 = "7a7418913aa6c3e5f5def9d79bc027376cbfccaa6bb334f0852bb1beaecbd358" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string324 = "7b4c65fae9cf9cb7ce70928fe6580fa9d077c425e1831958098ebc4537ae16c2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string325 = "7b5719a90750b365cd44f2798f2ccfa7e8ee513214cd9a8b9fee13569ed91683" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string326 = "7b603195b50a4b3822f847c97040e2397b0d34eee9fafd60ef6c0fac0c977a29" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string327 = "7c3e4ff39cf34bd825ddbcbfeae12fc2bc58adcb0f745686392f11963f750604" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string328 = "7ca6a195613daefad79766c8e784e3e8adeba912f8467b934523041d63e634f5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string329 = "7cdfe04313b09d98da9ab7526c10ebfad98eeefe1b3b6f7a8e35f689a03785df" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string330 = "7ceaba0911567fe17c4a06f63777411f452783aa8e9eabc3db3858e410e70580" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string331 = "7d6d7f8fd0a2ecdd1b81934fd7f0670c17d1f6aa2b67ba1b4cb2a214d1c7b480" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string332 = "7ddee6c94a33b7dedd603f12f361d2689ca59b41d6b119a806491ac76497ba9a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string333 = "7df4f0da54f3adc731f24f971d41040a2922a9822aa3b0a596b545502a638ef3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string334 = "7e041cc324312bff2d86542c6818e96916caa1e8737ff83cbc39ff9d20fc69f9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string335 = "7e1562d7995b291237984eafd847c018c8bf8ba1ac3869749a1622f119bbd8bc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string336 = "7e3a066f157ccb8e9fc9319c94561dc9bef52e502d73d9b02c0343f413a8c543" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string337 = "7e3d5037f8e2208067518a513ac921d2bc085beb97840f0939a6ef1d24443346" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string338 = "7e58ac2436868f98276bb647edeb7cae2c5cb68a9d4d4aa152b0c80985a72a3a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string339 = "7f5d1fdc074adeca5013395f021574003a543c78953ee17a9afe7fc57d628369" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string340 = "7f797dd35843b42edf29a19340387f2bf230275fc7941a1ef2b67468e9c1445b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string341 = "7fdc003748c1fa5ff0d87a64aaa8a029927596db53ee09248494aaebe3970179" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string342 = "8000e9b99094cdc71aeb1e81ff325681539b44fb3c2ad1b4e68164922b632da0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string343 = "80a4f4c0ec5a5397fe7acb53c5e517109ad3a8869440ec0305dd16bb9ee863ea" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string344 = "80aa71e1022cde5a50c19e15148994c1e3218960b0e9a2ba50782711fea564d3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string345 = "80b60adcd06ad0701c0f000d93d52d9bd4147eb0eb17089939b05dea0ae35cfa" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string346 = "80c53e7d1ba179d07e6f7863c80a7acc4bc06801ce08322e82bad7147ae535d2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string347 = "8188be37fcc477e98f40d455c59936ba088a9bb32628fa68ea0a3d5c3d6dfc7a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string348 = "819fef0b5e052b0f173acbfac84e3e5b672ff5ee789035d02aa813fb5ddcf48f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string349 = "81a217411829ecaf0af4a391b559a9ab78bb65de31eaa6bac524cc9c58bc4fc3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string350 = "824cde57cde28cf15e18e2eae0e68dda28ad89c33ddb0d6f01dd999513f35b68" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string351 = "82b2e4933abab5bad7a425ef7122157be4ab660f488f768f719a5b49017cda27" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string352 = "82c596e4b30f9be61f942b26948a5e51c6910e36073f6c5e531ddca8f60356d1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string353 = "82e0dfe67afecbff60f4442ca4595984ad82b8515c985857ac067eb4b1737f52" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string354 = "82e8b44fbea744b19d70b11e5c9836526d303680860fa39abed0b69835c64e8a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string355 = "83184461da759df6f22da0e53a4a367eccfce3b1e99941521181ce7a03000aaf" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string356 = "832b7b0c67c63fcc6abb02d937a3b631f86a934cdf85879eb1a0da5705b05c65" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string357 = "8332935d27f531b6c85fe79f76625220391930506c5debb44895cd8269f58b07" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string358 = "83415b22a293a7dd3445a721aafbfd17b24e8b3f0864d6a68d3f0f70efff4bd9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string359 = "8430f80dc17b98fd78aca6f7d635bf12a486687677e15989a891ff4f6d8490a9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string360 = "84b92d2a8ea328fac12eaa92321d3a5c61374f1dc9c7a9a6e150431b11354854" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string361 = "855ebd0013f114417417fea33f17bbad5fb49a588e93ebc0099f0d2d5f7312a9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string362 = "8578d2a63bbedd34669ed4cd8b332fb3aecfd3480ea3ef6d0c692e6fc146cb3e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string363 = "85a6408cfb0798dab52335bcb00ac32066376c32daaa75461d43081499bc7de8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string364 = "86a906672ad815e281944d68af3d0f7e8e48591b727a3215ed06be57dff8b514" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string365 = "870d0643bce12a91a51947e9fee61b2ccd3b0fd12c21e81bcfcdfd6248f4c287" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string366 = "8758130f7aa1639b1b2c24c327114657a819c81cdd229a41f56fe9a6550a2b05" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string367 = "877754ae2d7a31733ab7ee31c4db2159c63c48899bbbf0e7578ae9067c8bfbdb" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string368 = "878dadc0cd51626f39072cd599be261d184cfe894a4447298449def8588072b8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string369 = "879f2aff6d65c4ce886ccd74508a38dc49d4be49c37b98b88af45fb0f908e865" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string370 = "88165b5b89b6064df37a9964d660f40ac62db51d6536e459db9aaea6f2b2fc11" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string371 = "886e67a861f34bcd7094cc4d2bb989d0c3aaf594d11a21fc11d4ffefe136f47f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string372 = "887151c88c3be897947ce3159096518d452d30e1006b850a65d951387d2358d3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string373 = "887b0d18cc4158752105774b5b332ab290a51f08e2602b5c140bc2b1368d1b79" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string374 = "888fc4f6a333cad871710fca2227c37bef771323826c5c414492d653858db10a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string375 = "88f70507c3d00c6db0700498561444ba6ca5eff3afff4e0eecf96e7ac3668230" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string376 = "89866c382c09e09e89fe8548c3cf51c64784c914ab2b308ad7820ec6b2758e91" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string377 = "89b8fdbc6fab18b4544efbfd2c7929e02f5d5ba66942e8550098f43111b79a6c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string378 = "8a1df785e99e5bee6541eda2597872088228699c8877d83e5dabe94b07a63828" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string379 = "8b870f77cc8e76422967eb08ea3c420e7f85a8dc689a0b4d66a4d307c20916fd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string380 = "8beb7234aac02e5ca176c452da12725723691ca186c241953ed4b15643619f58" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string381 = "8bfe709bb0bb6d4e6976492ee41860bb06da468dd6baa268beaf6ba089c0a263" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string382 = "8c1c0d5652d1d4a77c1c48526fa46eedbaf2d57b96b5a9e632c2b4917449a912" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string383 = "8c341c2d36bae1817b1f31b77d5cc68dce21f30e59dd7ccc444d7b82ac88b7cc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string384 = "8c3ca5ddeffaef4c8481b69314dc10d2d8b7da4a2e57b4ad381596d15e9767d2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string385 = "8c76b3f974e99232e25a8e2e3f04d15edf581ee94f9deff8ffb147c817359882" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string386 = "8d2056b0dbb106c28a58f7652a7a40da94e417c951638831e2687ddbbc253594" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string387 = "8ddef07fe02333400b850d0893f14117ee05dd831c877a08e54a247da9e2fdbc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string388 = "8e24b029f4c9625430ab652fd81f3250c0f6d04390f7c5e7f7f19b4a7b9273d0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string389 = "8e52ca779ef1c3d2bc568eb729c3e2452cb767e091348ec45d374dcc4ddf6ec3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string390 = "8f68e92980c29558c0ad80dd89fb6823a710c7545a08ea061318f67e4fedc6db" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string391 = "8f8eee3e9651b9f7384a323ba3c26a5667a6388ab2ef8e6d869d3cd69b9f7c95" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string392 = "8fe928a203b33b847646d9d0e9dcf825903f7379266fab08ec5e44ddec9aa4ed" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string393 = "9010d659ebb3159009acff108d94c8347aa48f1c41c12176a6c7142ef7ddfd05" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string394 = "9062e56b98173ae9b000e2cf867d388577442863c83ac3b6a48e90a776cf75ad" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string395 = "90ff7409de18be284f8b8e1babe716d653f74b225b37704448fc46edb4b04c3a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string396 = "911a1b84f2100d2ac691c0bb28955fd2ab65e76cb2dbe651b21f6072a508e2be" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string397 = "9198c43abd08b3a09ea59226282447316e13da579713dda2d81a28c37902d2c8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string398 = "91ab146f1353958d24cc4d3c909de7bfb2d83abc348e5aa96dd57262c38a024f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string399 = "91b92f7f1c87b8b7ebf5ccc9b986fff74322cb349492852f6bfe7eb44bf8b3d1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string400 = "9242f2e59ea99bd890e8f92b95a91a4237df9572fc93c6bc64997d5705ae03bc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string401 = "9245cafed0bc3f0531950cb8f31e3b7c2711a2785c79ec088d554bb8fe16ae81" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string402 = "92a895f1fc289a338ff9008045e94525099421d66829dece14c9eb880f685280" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string403 = "92aa5912f3ba113f7a763afae465ec6cae0542db7e81a544e84db144526ca887" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string404 = "92e6621b5b0f2972111efcfc6e09c3102e1872d2358350901deea1d2d363776a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string405 = "93bd89817c42e31310485eaa1532e6431b557e2b2850f9dcbfa5cd6b4b60b189" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string406 = "9426eb3d0fe973759d8337e545a88489798fe415c608c0fe29cceabeac8f63ab" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string407 = "94d14e87eee41566909017eb8847693a2c1d81c3d448e8c01b1042be30757924" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string408 = "959bfdfe33740591330185406539399037eace2cd21bad62dc057db6ffd30656" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string409 = "95d33e96934486c49553d1c4f2371d92b257795dc8318ffcbded329117e83145" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string410 = "96167e823996cae90da9da2c7e686d966028b8204d0cb92f12535e055d15cb9a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string411 = "96257ac3f78ba98e844960d52a2341815c3c9af0d5293cf0dc253a1b7f2a7c55" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string412 = "969e56154298f0996396bf310bb745cfa549b2396765a49dc1611db1f118d2ca" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string413 = "96ac901e030641264cde78441b64bb6e20e2e1eb33b55b79408ecfd23bacbc7d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string414 = "96fc55faff503465ff38e6bbbb21fc6365f11b52756d0b82db3a52b3f5487af7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string415 = "9796b2639dcac4c2a68c53344b8382ce959d1b1e68798a9bf7877353c9ad2a3b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string416 = "97c9f305d684472b85157d1a2acc15364fa1999a25ddf50b40f5e76ef2fb8961" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string417 = "9827be6db4d39ec8963785cc91b176304d9cf7896820b65dbabe6bbe8eaef0bf" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string418 = "9834dd77457930e3d90e08bb26c0d14c29fd01dd9fb51292c1ac16cc93041abc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string419 = "98394683d8f30ce9fb313100f593dc16e97a52723b18d534cf586391a97cdc1d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string420 = "98f818a90ad8640c5f56c5d73ce5bc45ac0857d8a9d8d173d0101ee7e4aa19fe" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string421 = "99759813456c7857b5792debb24f09d98f946bf012f8436e94420c7195701bbd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string422 = "9acc803db3f5e4b87282da31d1f402958f6344c90afd74abd5609bd0a9449b56" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string423 = "9af5233ce7294cec25fa60e36a47dd8d0eac6fe4d0f6ab1180291545f4dcf5b6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string424 = "9b3dde2aa24d611f7042f7248ec066f29d243b8b351a1530d5b2cea145c6dfaa" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string425 = "9b5ac6a354462e1d547aa65f9c29632092a93861190b3c0a03534b1ec016a5e1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string426 = "9b7e9ebb1641ab9798d06e550317afc5999c25eff3abe28a8f21b6344fab7622" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string427 = "9c3aa9197679d1cee2f74e0e1938ebc759648520d3cfb02dfb7f0422bd234e2b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string428 = "9d2f44538ea0c6309426cb290d3a6b8b0b85de5de7f1496ff40c843b36bf8a8d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string429 = "9d3d2e4222e2352d476cfe71afba982fcabd38e2e5c27a43bc126de2c33e353b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string430 = "9ec893fc952f4e45307f8cd603b6de2f396e1ad757af6847c00a148257c0dfb7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string431 = "9ee0e699972c2614e3b1eb3c803caff659a64bb8d2c14ba07d520944758cf0a6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string432 = "9ffa244293433033702bbbbddf85e116221a7ff75c0b2bd152d9da8b6263ea6f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string433 = "a0f82a1dfbc7ff306b986ef88ecd57d1ab08f499cee267184bd5cdb5d9bad6a6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string434 = "a10a8b566860339bfd6832fc9073862c8689a1645236ad3d4eafa500f9c536a4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string435 = "a1ad8df9d1ea7ad06e8d124238448640fdaadc708b61e38ca378de15aac47e5a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string436 = "a1bc2b5bd61ba0f7babdec16c86b0715156d3577dbdbcd2863a2b2fa19df7606" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string437 = "a1fccf26ba0a2f7ae387b9e639c8e87885ac5fca39e9eb3a24d7386d296252c2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string438 = "a1fec79b3327cadea501d3dda9437a38184fc2ef3981f1b8d92245aaf8213007" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string439 = "a20cd9ca2f6e691c531cf7d30c46bfadce77e609c90a5fe4b37254f14e5a934f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string440 = "a2299ebe21ea5937b4a8b561f951eb0baab03299431b2142af521ff7f230045b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string441 = "a27ce45798527f143d059cfecd0d2c8e976da75ae6c70f4eaeced862062f044d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string442 = "a393bd2a8a781b63fd58b3b343222ff70c8f7669be23078f844a101144368800" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string443 = "a3eacf76e0d6b305982cba0115dff905c8de86bd2768011b41338f8d276e0c1c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string444 = "a4239ce6da7f2934b3d732865bbfe7a866efbdcda80258bc4a247d3def967f9c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string445 = "a47c13e667e16a8598e32ae5ed11e2d04dc8846af682ea3aebe42716e964a278" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string446 = "a50a1a9bd8b387a4e1762adb62f09c416835aa15de9a27e79815b5b62c5951ec" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string447 = "a5581e05f792ca9ddec49004a9e3c9d203663e1b2ab330364d1e6ccb32bd8226" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string448 = "a58c0cd4b456e360cfda39c325137343484606e93b500142a2a6730dd0b9dae1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string449 = "a6e54383b67446523cb54671b2ce35167bd8c4b9a507025862fed74f0ebe27f2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string450 = "a6ebeb84345adc07ff6fad6bc4e8f404dbad73c106a6e2f8a7f635e062efe9ed" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string451 = "a7a82eca050224c9cd070fea1d4208fe92358c5942321d6e01eff84a77839fb8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string452 = "a7eec25a26998f786481137e8bca3b7fce2275502cec2221a01113c7811fbf48" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string453 = "a85ff11195be3386ea7d68cb9bf2fa7c43896ce22b8a5f95b63b5737a6fb388e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string454 = "a88ca09d1dd051d470965667a224a2b81930c6628a0566b7b17868be40207dc8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string455 = "a907b585267cc24f1b884ace352eaca2f987c0aaf72b344a6b0da8264c5cf6a9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string456 = "a9080fc18d6015126864873dba3307b2b9c8ab5ecf79da3c1ae25cb2988fc9bd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string457 = "a94d6c1feb0034fcff3e8b4f2d65c0678f906fc21a1cf2d435341f69e7e7af52" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string458 = "a9507a67b50c7e4ab38c2334ef037a78ca5cc257decf1d78b8afbdc0fa73ee18" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string459 = "a9c88d5288ce04a6cc78afcda7590d3124966dab3daa9908de9b3e492e2925fb" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string460 = "aa834effee692d7aed5973dee1d810420c0d3b98eb8a3b89620c207bff01f78e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string461 = "aa86e5667c46ab0bdf8ceca80fa3c8775da2bbc18656250a745ac8b042837a70" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string462 = "aada314b9afa5936d4ed401ba925106c20b07908ca39a9d363e0de57a99759ac" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string463 = "ab8de228f748301d39294ae37b82aa068a47c9d36b42fd23c06afcb3375da1cd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string464 = "ad4f5f6a6dbfe7ea29037f8d3a04161580cd109b99a3b474766927b2bf160984" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string465 = "ad932c8eeb195c5880274623fff8fb7f97c433133db49c29d46ad64fcdcb5698" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string466 = "add9c85b9fd3f3594d0630518ba59220b9eec8441205b2acf8c61d4068003eeb" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string467 = "ae4aa8f67e7cb800e060a454c72db0d8c0f8a94ba3ef520526c6d5df7f384995" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string468 = "aeabbac9038f4826a043f2adb165c46b6e2af47bb363aab713f4841b793d5406" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string469 = "af0592eecf1901f283b08bcbd1054f6ae50b5703c2da9ed8a4dcc858220de4a1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string470 = "af5c388b467a78ceba2e47c2b1840d28209f1d2c1063b21cb20d79ab18ef7956" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string471 = "afb6a4c0f19afbca0dcdfc6daecd05db72440b9f66be3b226bbdd3d601d256dd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string472 = "apt install restic" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string473 = "apt-get install restic" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string474 = "b075acc6e8a6a1f619752b6106299e66ff7fc95032bd9a9096718c7600bd5c72" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string475 = "b095c8ae34961ed96ebd2cfb8d99d0aae0c9194beee50efcb55743a56a3f2527" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string476 = "b0d62a246efdf89a35137f55d840b7f7d1a6c231a4a2a14bd4ab2375355644ac" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string477 = "b1213c190d359872abf866bbfbd98b8140e16177157d241330b2ad172fa59daa" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string478 = "b168ad78533011155648042d2900398596b0b128d12aeab2314424eb8be06794" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string479 = "b17778908c7e0b879b79b4aadf2dc28e9361e555fb68b35243c325b390628eed" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string480 = "b1cb1665e707241d9b0df4443c75ecd01f036562b1ab0d83eaf9a6fb4cfa018d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string481 = "b27ceab87644e8402f0a72d5f84bfa6e52b4c9c31293fe42fef6edba58fd81a3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string482 = "b379d721a766c8b80a121173be37050c9ecc94b11c5dbb0e246308ebbb5fbe74" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string483 = "b396b58b9729c83406ade3cd3f6d52820a7ff6cf36cd4a59eb9d87ee267591fc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string484 = "b3c09137b462548f44d764f98909534bef6e85fe029d4daf60545642cdefd3dd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string485 = "b3e1befd68844e32730608eb0bd7465a4e634154ac4a90ab8d48738c05054e42" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string486 = "b52adf7f57f96bc43c7380afc6aa2f549b530e42436af53ba5b6ca4a75ed343e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string487 = "b61cc885ac54a8f87869094cb343095b341e0db10898d2889942632f6155f1ff" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string488 = "b626b5bb92017ef63e3450aeeeb50583be95fadc09e9d2f44c5f37caa8a61e59" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string489 = "b8c838d10851d63bca4f99ebb22b29989f517c66ea950eb0a9d7a4d110d2e86a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string490 = "b91f5ef6203a5c50a72943c21aaef336e1344f19a3afd35406c00f065db8a8b9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string491 = "b95a258099aee9a56e620ccebcecabc246ee7f8390e3937ccedadd609c6d2dd0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string492 = "ba1320c819ee2b6e29fe38ea4df592813e7219a89175313556110775f2204201" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string493 = "ba4393a03124724ca068684e02727bcede7e897eaa3698362bf1a452d1ed5823" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string494 = "bbe35e6cee0f2d86632a419a45fc63ec44eb1ef01f14fe53c5dddb527545e16f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string495 = "bcbd51fae14c1b87542a6130b0aea2f77d888615bc2ebcc517977d56ed1fe582" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string496 = "bcc708853cb655ade9ab3dba63fb1a585508ca1f55fe0ec41d97f84c97a25495" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string497 = "bcda505dc0c24c5a438490cb329180f6215a57d3fa5c1209570b86f9472f0474" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string498 = "bcefbd70874b8198be4635b5c64b15359a7c28287d274e02d5177c4933ad3f71" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string499 = "bd6f57c36d0cf7393e1dcf6912c36887715864945fa06c457f135f9ea33fcf41" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string500 = "be4b5c4bf5fde4fe59cbd98a5691035d5866613a2bb53ee8588d393ee14af667" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string501 = "be707189365dc12e5742234e07d2bae35ccdcff0de458dceefd4812796fe2fb8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string502 = "bee03789cb90ecea446cce9211600312ca43c8ab4c6231ea64234b65eb2a5b82" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string503 = "bf1dcd0761b81ba9b79c01399083c6df74b709b44303ff01433753a9cc731caf" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string504 = "bf6e09743df6899a02f0647d899fb008932760ea872667287bbc47b42091a3b0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string505 = "c1309a2dc51340d2115e3c5e2ad31917c401132406e92774b70c2470ba631e7b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string506 = "c1439cff56678f08ca43ae32b4842fd43ada6b2c2798e647250e93bd32687c26" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string507 = "c1adbf4fe3244c1e53659221eafb35da0de80dd9f7c653dc1cb9b8037f8d01d2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string508 = "c2cc496b63e67636dbde1d94f31f5c36eb532f11953a36c56f7aebd7077befe5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string509 = "c3145c4f1e747ef9c1b2f953291f96f87abeb3e9686e8a91340ed4bd191d9941" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string510 = "c3224f8327d7cf805b9447314f6066bec357dce64c60a0937aa3b8eb1458c496" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string511 = "c390aca094d308acc9e06e4375915c05c9aa1bb67e407e86a6b77e59de694469" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string512 = "c400a97000f7567515c3ffa560694f83927c8a77add8da737f567b2ff3812054" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string513 = "c4677e4eaf38ceda97841c8cae883883e026751970b41bb1a3f5e0610e07a5b1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string514 = "c47c3409ede8542ee139232513fe3f1c30b0360bce5d33f65fab9a32f9abb802" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string515 = "c4c8c47da78cce55a75fb1bd7f528ba5eb4a2e2f96ae1927a705bac7eebde224" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string516 = "c53a614a1a1536db55204e938e84708de9f18c42b613a470e46d433fd83a6db0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string517 = "c5d39c81e4ab9e8ec45e8cd742d449ceb944b73fe90cd24aaff3d89bc7ebb3e4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string518 = "c5eca1ce456b855510b7da24a0204941c5d7a516da8b8b5af6a88f258a1994f5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string519 = "c6f0b7931f8df1223c5edb6adef3919350e1eec95c9493748fb995c2d968f672" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string520 = "c703e6aa71038579068c826ba7f8cabdfa61de7345f389cbcbf779ef5c3e0767" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string521 = "c7652b1555ab67b927ea24b856f1a81cbd21067afbbce16ee6db88022714dfde" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string522 = "c792d1729f05d22140c7e71092c3ba3314d7a9b2cdd9022160b60574e50a9826" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string523 = "c7dca90fb6fd83cee8b9f6a2776f5839794341af1953d251bf06a91870be7a8e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string524 = "c7e58365d0b888a60df772e7857ce8a0b53912bbd287582e865e3c5e17db723f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string525 = "c816973d0005248a7c6112026d9fa942e8e755748f60fd4a7b0b5ca4d578bd74" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string526 = "c83782cfec55c5787d0a2f1dbaa3e4fb36eed7c164036fcabc1813ab314f1932" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string527 = "c87e364b795ed06a18e5d54ac07ab31d11f343d66bdb5779df4d48ad915850a1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string528 = "c8da7350dc334cd5eaf13b2c9d6e689d51e7377ba1784cc6d65977bd44ee1165" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string529 = "c933ac96b502a02dbac31a1b1e08cd9e950274b9cfeae80eef0ef59a1157aa48" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string530 = "ca5a7ecdd5f4a8c6315555fb446496b2085137d6d38e56a0d1318c5e1d80db1a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string531 = "cad474e11c4a63c30d9807392c649acf15736fcb729e1a42f1b63a1a062ef62a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string532 = "cb5044ef22deef19afcaa1d37da6d2d1e89a21f5cff3e77ad7c47ad8da1a8a7b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string533 = "cc53f743f393cd710a36b8842793843a08b102b603213f0ef43b58c19ff01147" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string534 = "cc90db8e72fb9f65c61b95463c245e7836a8fd7ac375b79dc1b01d2bff1a5bd6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string535 = "cc99b5463667c5a85d430ad159b1780d63b61d4bdd08b56f5ecabdb264679408" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string536 = "ccb0d8983c1937aded1f217dd002be4ee9d274cbd0e775d596767ca3954090cc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string537 = "ccc327a0e562c42e1067d7082e00d89bb37bb5baf5433c0c775ae8dbf2a6463d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string538 = "ccefaabe2451d9b11d6fb57bd449b60526a760b6ed92bc6bf3614858dbb861d6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string539 = "cd4a93475e0410a506f0453e5b884b2b31f64d0ea65f287c97b34737232b2768" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string540 = "cdd52658f4836d8767e267931a90bd187a8d81c4a0df548cf0c4056bd5fa73fa" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string541 = "cf22ddc0de9ed5121eea525f5a701fbf7581b515372884d3c27c6ab6becb7d92" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string542 = "cf7f543c3e8144b822f184d610284ef2986e9a9fe4482c377e71d7de0eee6336" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string543 = "cffe4f305bd8e92604ee54b41ecf0f280756c25ca65170e1e8da031a3e269745" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string544 = "d0cb6aee67e6002397f2a03aad19364e456d597ca2c632087530d19c8620e0b2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string545 = "d0f33de8e813474ae320912f13a929d763aa012d38c706fb76a46d9c7212f7f5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string546 = "d1082f06795f50679df66d5bb31b29f7d02e7932ae0da48a972edbfcc067be90" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string547 = "d166b7b1c5a74e9b9b4de99113c7a8e563a782d17664c2ffbb7e721df1062ef5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string548 = "d18c1c2f4445bacac3a8bb9bf32d450a25028a7c94b30a1bc040942a5b47f661" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string549 = "d20f3e5c4081117ace9966329f8460b8c24ff862794a98233b4b23024b9efe58" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string550 = "d286f6313ade8206ad883cc2c55605964dbf469524cec7116a736d11d389eac9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string551 = "d3afed5d69df35d875e4243cd45f9f539a69c48c8f19f9e59ecc4b2422dfdb4e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string552 = "d3ebd06d4b88d5e4393e19b093fc74c773cd41db3d3a04662864934d5cf7dd05" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string553 = "d40270cb6d23e194a1ecb483a41ed42d9edf803b6c207b7599ff5813036f5e5e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string554 = "d4b4b82d0662242a987ebeb97286034aaebfff210180986e023a56513a1a300f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string555 = "d4c1b56d9fb1ef2a6e3f9475a9a0ef9fa822a3e47dff1c3ca4ddba2b3ff0e68b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string556 = "d5306863ae3c851f030b46f8a01db4595170dc8a875bf7e527d697ae122ae1bd" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string557 = "d736a57972bb7ee3398cf6b45f30e5455d51266f5305987534b45a4ef505f965" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string558 = "d7eee6b4038ca7d25bd062a2fabcf5d2c5683a9e59623d6a6a25472ed877f78f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string559 = "d885e7309ccdb44151ee091e2b75c54cdcb02b701ff6e4de6217afad5eb30e6e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string560 = "d90e2fb20e7db4b605b0de5eac4f830f38f94fc2093cca54cb6eb7b4c46d68fa" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string561 = "dae5e6e39107a66dc5c8ea59f6f27b16c54bd6be31f57e3281f6d87de30e05b0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string562 = "db351869cc3fdf6b88678f72515adc4ce5600462880100306d5597eb3e2ed516" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string563 = "db9de96c8020db93542e0abe95168831257d9ab6e68ff0430e28deb019e31640" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string564 = "dba96683300231f309727df9f7aa6648bd50d67ae0babf6c3304ab212bd40d39" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string565 = "dd420764e615be9eeca958d60c1adf0e7ed806d2de93f9638b5af105ffd7f007" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string566 = "dd518c110de3900f1df5bc5b042508e85ece12f4906e5868803e1a00fc2aa2ac" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string567 = "ddf89e5b9fd98708bf83fb8bbfb3c7baed2d5183035bfc0c794507d509235072" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string568 = "ddfa313aa3d4038579635361c32c98d8a885e8e9b7f53224dd0df22b42fa618d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string569 = "de63f778f0650db9c0c00c3772d7f87a6c21ca64e1249e55392ecbeb9bc352a3" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string570 = "dea0f108ba1485baca081dcb34a83c472a0bfa75e4f8483d3c2fce06229fb06b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string571 = "def06c3e5b0c881be0f66be65c9e78fd8d867d42acc12e60a290a6a76c2b4d77" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string572 = "def48c83f905c40247c041df1797df5ee70a2b233f15f559df160960edbb150f" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string573 = "df0a51bf7623a3d0c67f707feb0a086fd15d08a6e0413392fca280e540854fce" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string574 = "df278eebd151b6ff62ceae968e3a4203a58d447712ec3fdb62551b25299a61e1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string575 = "dfd2a510010aa652da30a1d05de760782d9e7dc8598ff9f1f3d4da2d734269cf" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string576 = "e028c07ede569edf05373d2f271fa4ae6f4c0ecfed56c1c22d46b1b3c85a34df" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string577 = "e0dca6ebd175563726b1a7f83614b53194a8945421241b3b2fba18784bc4db7a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string578 = "e1167085d98313b940710377908862a133a471e476163d929b16fe74efee5356" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string579 = "e11bbacc2254a1aaf69807117f5dd21bba924ff5dba6bff978a401bfee10640c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string580 = "e124760dda781a328d0ca851b38a124eff12f1814fa4b70458565c69b546559d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string581 = "e1aad78efc4a500f13014eacfd687f10060d703e896efd1c60930e3167e4d2ff" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string582 = "e1d81195194f684a0df34da1b4ff305d1c033283521c02f36a6f5cdeffcd6f2d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string583 = "e22208e946ede07f56ef60c1c89de817b453967663ce4867628dff77761bd429" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string584 = "e245d857b943531a9617677179564e03675f992c6e4b6876090279b1fa8f3e7c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string585 = "e27f8c61205a5fa71ce1d1dc4f3a79f10d58ec2fd7f05b07c26a4742beaf4edc" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string586 = "e35620841c35cc70619f963842c207107b9c52217e4c807c72178181ad5e3695" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string587 = "e369b92cecfa897281c727a565a81ce86ab629088bde9d95d690ad86284713ef" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string588 = "e373f4331ba91d4862d2b9f8646c9e18e20b93445cbe203ed86336cbfccab6d8" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string589 = "e41dc72ece30584c3e9c7772ba01a9f17e4e348805521382d16299e4694ac467" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string590 = "e4a6b203697794386d11faebc4da7ffe7c03262755b4ac64e0c4ae633eccdc0b" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string591 = "e4e4ef54d935c9de34f40e748702f5cbec400bd36b5977a22fcf1040d6945046" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string592 = "e60e06956a8e8cdcba7688b6cb9b9815ada2b025e87b94d717172c02b9aa6c91" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string593 = "e6139b506d55565bb81ff034a8ec03349ee6f0938c27cbe846f22853e8770b7a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string594 = "e63b787de388b158b538006003db536fa48dec43ad26080afe44d42d93ee2115" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string595 = "e7ae22a62f42e92811bb79ed2a268d4794a640a1d61282985f5dfd1b1d583b60" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string596 = "e7c7c93448d7780b741496d34b10423f266ba09a8ebf1093b6d186e1f4c9e60a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string597 = "e82bcb39e340b7dccdfbf649ffcbef1f7ca0d90e0d217e29bb67a95dc1cdab24" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string598 = "e8c7827dae5c757ddfdd23ef8c97c24315a9c06dcecdde7ceb45dd21145d7a2a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string599 = "e8ea6411a9baa77588224ebbe6ebf21517cfeaf9b1933eef19246f955beaab4c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string600 = "e94efe0f4337a2d8d91bf3933d6bd71fc6671fe5045d65d977448b3f2c7747ec" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string601 = "eaaad7b12438c24759b68cd6b0652598125e8a34d1d83c581191418822b6f851" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string602 = "eb8b75bf891ae654791aba1d7ac98f4f528d1f44cdf3f63604a4de92b309e5a1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string603 = "ec2e688f44920bed00a0bb87ec28be0d40dc7ebdfd20efdd4734afcc7b132207" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string604 = "ec5dcf71ec36103aaae9227bfc4090d5ce3c9e07a184a2150674c7b70f0d63d6" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string605 = "ec72c50bdd6b49a4a045ee92e471c01596640426aa4f5cdfdce2c2a975a2913d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string606 = "ece898dc29881a952b5e8cbaccc17dc1fa546d61910be9cb8be05049af64ed78" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string607 = "ecf5f36c4567104dff7f7fc83958a2d03fce1920ab7cd37fc109d10db75620c5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string608 = "ee3caa7a4881716651aa159df73e817c7a7d3fcf82a234d83d3f78d4070975e9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string609 = "ef7bd67653ef87e73212d92560a12c430fda7f73b86d9eb9865123c44f2dfbfe" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string610 = "efa3e8453d29c9a5c581f0ff42a6aab237ccda2ba1b545d013ba1a2adaa4348e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string611 = "efdd75eb5c12af6fec4189aa57dc777035a87dd57204daa52293901199569157" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string612 = "efed00b9707b548838bb7010f9d42b41d8e2e4eedc6a2c3c3487f4e96d7439a1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string613 = "f0078e7c09aa38b301ec1b1679ec97bc711a178da3ca48c9354c08b33933165c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string614 = "f0474b15500edb41cb2eb6c7091bf96c0fe3ec455b8c0559974fcf1a3b1668e2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string615 = "f05d3115ca5636a3a30f454f62c51746473121d40b9624dd28d84589b8e2eaf2" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string616 = "f1a9c39d396d1217c05584284352f4a3bef008be5d06ce1b81a6cf88f6f3a7b1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string617 = "f1fd018de5da0ba61e095a731ec6e142c9cde50f6231eabb475a889fe5f323d4" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string618 = "f1ff71f1b4751329a9957412758931f8b13a9477dcff3435ee3b9ba98a6ace73" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string619 = "f27c3b271ad36896e22e411dea4c1c14d5ec75a232538c62099771ab7472765a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string620 = "f2b2bb7385ee56d98659c4a0dbf42eca46227e10f92183a92934f4d96d523501" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string621 = "f3c09c7cc731000a762f816214dcbe8936eb470992d8c04c1439d436c09f26ac" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string622 = "f406a3f05847268c14ec391457680b2fc6372d5e506c153de5dabe8268751480" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string623 = "f430a8069d7fac26e93994f8d89419e5285acbc0fb4514c89f427a070614af2e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string624 = "f467c57b696a4f23fb1655091ee0af941318960d53fb94bacc4e9162585f4a0e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string625 = "f522b356e994e001db129e2dc3f813d23b09327c623a567593cbe9dd4e130ac1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string626 = "f559e774c91f1201ffddba74d5758dec8342ad2b50a3bcd735ccb0c88839045c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string627 = "f66e099b3dfc1bfa8fbbcbc04eaae20961e1b27fbb3994305d3dc7251a88da69" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string628 = "f6c0fbaa3c9181db206d10a474c7c977ce274cf8ff7f7b170e5651a00d283c68" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string629 = "f6e25c33ec23c5d6864468e4839076fa3f6613f67763f054df545a2fbf58828e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string630 = "f7f76812fa26ca390029216d1378e5504f18ba5dde790878dfaa84afef29bda7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string631 = "f800aa3832f7f6026d8bcb866ffd08a791ff0fee061520a9759549a0ea63d0e0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string632 = "f818778b135d3b0ca9710992e13b7e06458fcde3aa914b60907aeca7ac84bb5e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string633 = "f8f06d08c202c37b3d6ba70e0ad208e64d8673fbf6031e850dfc6d673cce6e44" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string634 = "f9ad4d91c181da2968ccdecb5238bf872f824fe1e40253f3347c4025192f19c9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string635 = "fa038acf7cd53cad4e1e6aef7d73a7a2c4eafff9fd344db05ff725884166e58c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string636 = "faa846645677d0e4da5812851326f4f18b7310d53edd380ed93165099395e4c7" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string637 = "fbaf3740b294ecd0cebcae3e5c7005b6fc9897357b8ee050a30c01cccd3b2019" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string638 = "fbb5435d1881e4a8df856378bbfa5b83bcb21ec9163a0690c63b88a83274729a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string639 = "fca1c44409a39abbd36c9326a96a8470022e5e48d436b6c57fa4b2735d69405c" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string640 = "fca3229e1f47db94e4707350c7b8fff9cb0e27d61d130477ad0ea3dd3808da67" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string641 = "fcb302a952c8b928788cabbefc0e8393eed884ec306f9d0ea9b3c109b8f31f40" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string642 = "fcb8cfece92e787dc07616f7942b8632e74c24bafe6de1d0245543b9c7010a76" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string643 = "fce382fdcdac0158a35daa640766d5e8a6e7b342ae2b0b84f2aacdff13990c52" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string644 = "fd0df9fb27d39a7990ecb66d872798148d6954207d653510035e087e1b6218a9" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string645 = "fd36ecab09eb04dab2aadae09347fcb19ba8d020d1684d4a096402e0aed15655" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string646 = "fd900c4347ee081a5dcd7bd1d33cb748621f72793fdc63becb9b0410a14df494" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string647 = "fda4d4aa167c0baa4ef5159613f090dcc61b265108cc93c98c9bfdcbd6a486a0" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string648 = "fdee8d4b32f8da73f39a0ee525a90343b663edc671c520d97e1540b41531be32" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string649 = "fe0c598004e2f3453bcd75e0d3ea77372289cf17302f162089b3c544a54d2216" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string650 = "fe3115fada63d6efd85cb0e3f7a9c52e688004334eef6c0d7349c39b64e9470d" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string651 = "fec7ade9f12c30bd6323568dbb0f81a3f98a3c86acc8161590235c0f18194022" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string652 = "ff1a32145246a5c3e38142aa015cfbcd5dc046674d0a3f16979ff6c4eb1cfe6a" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string653 = "ff955edce7641fd51844726398cedcd9a27d45f74731ca3c79a0abab5bf5ebc1" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string654 = "ffba5315499b161375d0a2e0f54789e93d32383be19ec2b7b1a8fe050dd9af6e" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string655 = /http\:\/\/.{0,100}\:9000\/restic/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string656 = /https\:\/\/.{0,100}\:9000\/restic/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string657 = "restic backup --" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string658 = "restic check --read-data" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string659 = "restic init --repo " nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string660 = /restic\s\-o\ss3\.bucket\-lookup/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string661 = "restic -r " nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string662 = "restic --repo " nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string663 = "restic/restic:latest" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string664 = /restic_.{0,100}_windows_amd64\.exe/ nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string665 = "RESTIC_PASSWORD=\"I9n7G7G0ZpDWA3GOcJbIuwQCGvGUBkU5" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string666 = "RESTIC_REST_PASSWORD" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string667 = "RESTIC_REST_USERNAME" nocase ascii wide
        // Description: backup program used by threat actors for data exfiltration
        // Reference: https://github.com/restic/restic
        $string668 = "winpty restic " nocase ascii wide
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
