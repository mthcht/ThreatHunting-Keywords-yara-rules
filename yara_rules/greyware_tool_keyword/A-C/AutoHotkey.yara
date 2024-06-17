rule AutoHotkey
{
    meta:
        description = "Detection patterns for the tool 'AutoHotkey' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoHotkey"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string1 = /\/AutoHotkey\.exe/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string2 = /\/AutoHotkey\.git/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string3 = /\/AutoHotkey\/releases\/download\// nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string4 = /\/AutoHotkey_.{0,1000}\.zip/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string5 = /\/AutoHotkey64\.exe/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string6 = /\\AutoHotkey\.dll/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string7 = /\\AutoHotkey\.exe/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string8 = /\\AutoHotkey_.{0,1000}\.zip/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string9 = /\\AutoHotkey64\.exe/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string10 = /\\AutoHotkey\-main/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string11 = /\\AutoHotkeyx\.sln/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string12 = /04eb8295af197da058cec5a2b78b8b7f6bcee7299cbadebf68dc6837968c5bb0/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string13 = /0759be5242a162707b9738226af1a163a15fc6e0105dd88765a52e056ac136c4/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string14 = /0c9f95a64d12580994ffbdd1ba90e8e020a97056d06615c3e6ced6001a7beea4/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string15 = /0d0811072bcce0b852fe3b5da38b12fdbc8e91a419df88c0ff6b09ba0fcb4ca4/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string16 = /107fd4550d60e934e88f65b15a00c8eca224f279ed593288d5ad9743ef7f35a4/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string17 = /15285219ad07eaa012de59c3001b67f65fd7382d913fde559219ab1f180d6fcc/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string18 = /1578e1c16807f4f9c02cf9d284cf774ad4725b55f114dae0778a2f29ff9e2c47/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string19 = /16089612f48695d4bb779fc1eb56596d264a54443ba461e8b9c4df9afa7cbcab/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string20 = /178f4b8888441e6970682416279fb99a5ffb2844136440becd66a8c62091e435/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string21 = /1c8697533f19519535ac3679b54beb9632476b3f13adf0d58708b6c4db55e310/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string22 = /1d9e35fcbf660435ec27cf36a00e87d80928f36e8edb2d7728abaa00585dac08/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string23 = /207fea03708f1ba8c8e61f30170d799495736726d1853d7d4150a5ffffa14013/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string24 = /20878974725227ec21e88d6e91c9ed2615981faa9ab9ee9821268008fd0cb1c7/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string25 = /20d41f5fcfa4f3d61c533a9e21a019f0bca0bd8012a6528ccdf2621749a122ab/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string26 = /24351cf8346262f0dcb4bab290b55ee65de503921906f13dfd106ef259d5fb7f/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string27 = /25ce0fa078c6603a909bb391c1cb4eb891554b29ad275beea47042962576f4ff/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string28 = /2afc21c42cca8caf03b00e22e95592ff6cbeb6ef64bd816eb9d32ed260818cb6/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string29 = /2c5626009786be43363b7ab1c2cca6a7b0eb57bdf6c40464f2abe874341b0485/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string30 = /2cd1b00947abe2df2cba3997d7bdd5a9043ebe598987f0e9cade0aceb73f9edd/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string31 = /2df6d9782b8656772c842c22b6582ee91782bde800f345491a71eb72c294e6fc/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string32 = /2e57c62a9fe28ddf0a4da23123c2622652dde869c366f6f1da6ff8bf78dd50c7/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string33 = /2e980bd99add2b0859b0bd6586dddcd688e1f8588ef6c9bf5922674e947a6dc6/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string34 = /2f58a372dc62e70149bd29621cb76049c438204127426299b9a8bdcff002c23a/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string35 = /314215d36ba200db6ce4ea71ff15203b3b048203621329269801c6c27042ba7c/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string36 = /31bd31d107caf59b48fcdc9af0f428d80aafb0e1a7166b32aa047b3b495d8457/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string37 = /3225d34d16ecfb04fca67e9ed68230ebcbe65bafe70b12ca0c687a039ebe0851/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string38 = /36d16c928a88a7a600fb6d3599f13e1b601c79b0eafd7cb1e2dde43d42893d0f/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string39 = /38b5790e1fd1bea17231a3a55e701217ebde42428046e029f609b1d1734c7140/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string40 = /38c646e446ecfec33fded951544ee72eab17433e43c997e9c56bd7ccf1d7aaa4/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string41 = /39037993\-9571\-4DF2\-8E39\-CD2909043574/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string42 = /3a2f34f529cd12950c905d2c68637bb071a12ebd0c00dd887d807fe6c23de762/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string43 = /3d064459b1bd3505d03217197c2dfa4db9efc0e9f71e6caaf1706ab8697b9a03/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string44 = /3eb961a803189e9d9d3195464a55acf9eebcd5f626c7e176c906b9639f43169e/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string45 = /3f1b1ca2800dbae254969ed5365848e4fbcf8725ec68d265c40318fe7e3d51a3/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string46 = /3ff847c73e2ab0d5f1f1440046cd001d25639793a352d9558b24708d77ac3127/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string47 = /411ea6ded074b7a3e461672d528e2a8e80bddcbaddcba7a2addbc4399e44d140/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string48 = /487413ff39c7aa044e1b5ab8a0047d6ef7c9c25550fec4d91e8a0a97fd1282ac/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string49 = /49a48e879f7480238d2fe17520ac19afe83685aac0b886719f9e1eac818b75cc/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string50 = /4c517113f22937a313921b73c9b25463cc7ed0b77d9cf42b08b6443184e52e90/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string51 = /4de829c7a5e19e8578b398793c952c1ea1a3a1df54f354f46ff140a4932da53f/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string52 = /4e07de6f89b7dd371735d0360afc61ac21d19ea7c4b3f020e2e1a6b17b61432c/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string53 = /4e1e3123dd85d3ac65a0803b08dd89b9b12b5a00b9f566782855332d03e5fe26/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string54 = /510a833bdd0f896cc398eaae4ff475f5b7cfe37649efbf647b50d21e442394b9/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string55 = /52a8249970f72966d7fae76ffc7fd4009ce4100e92ece3fd6c409c61943af492/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string56 = /5eefcfc824818b2cdefcdf6719f5db13a4800434146f0b90ca3a30e2ad6e737f/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string57 = /60d86368165d01d88709d304757abcc642b0c165379438023fb3bc791a5b749f/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string58 = /62613da1a6ac28989c8b3a7076bb90af9c9361cacd76c695c381140c1d9182db/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string59 = /62734d219f14a942986e62d6c0fef0c2315bc84acd963430aed788c36e67e1ff/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string60 = /69b21d5a3d2bcc2b2b075d275a38f551997c45f28c9504995ede406aa101bead/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string61 = /6f3663f7cdd25063c8c8728f5d9b07813ced8780522fd1f124ba539e2854215f/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string62 = /6fe778623ef31eb224b4aeff3eaa73aef6d76c091fcb328782046e1ec44969d5/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string63 = /700d65fb0b7653666b1ba1b3911f97ec9a6c6af647083dafd8609ffcf5499b4b/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string64 = /704cd5aaaf2ad78e31ce1b7e13ff87c7b5e97bc5e2ef55188525eb7c96a53232/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string65 = /7237594482ea47498b240d39ca8e94e3c635dc66fb4989db47739a8a420e6fc2/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string66 = /7350f50c3fc022d217821e6f416497820e6216a714c5ee859af1f36be9b740d7/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string67 = /76EFDEE3\-81CF\-4ADA\-94DC\-EA5509FF6FFC/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string68 = /79d6da35083dc0008ed1da0396c561994822b84bc679d7d6193cd70b1ddce0ef/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string69 = /7a0dfa37846ead5afe73e4a8525eb1738d3b52c608291ba37088b0c037abde58/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string70 = /7b71b013061e80d7fa52560b061e142f9d7abf38d847da9d6871a90f8cbdc293/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string71 = /7e570c5aa02fb16d74433033fdcdd74f890d8eac26b9b94d24f600c9e48feacc/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string72 = /876dc6fecb7587bc98ed1702f11e01f19f7c56cd9703c76b7722e914e143280c/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string73 = /88c5d386c60a15d9758570e8b261f6b1d23248bd37d32b98cdf83ebc5223a266/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string74 = /8dc4871ac544d2cd0ff7ccd84b8862eaf9ba0af18bd5b71e29146b17e4b13783/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string75 = /8e596f227367e273468b5833ab4169b6994bbfc5c1a2a3b85796a769f9444836/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string76 = /8e61b9221dd7aeab8c362c7d580eec35e192317bb8c645909e0ce95b91c1332a/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string77 = /8f0ddf90f4cc44499bbeb0f2d3ff298cd5e5d206ca759535495ee767e83b6023/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string78 = /8f28c38a0b2af6ac96c4a7e1a2c0f296b2410f845d9aca8487843a1edac4271d/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string79 = /9195ca93854a739d434ec0ce62ef7b6fa159402624cd49b41a5ad1f3ad8f138b/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string80 = /95142d0b33c50fe5fcdd5d9d1a1ec7951bf662b06f09d83438410cba625aa411/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string81 = /96af0b4438274122ca3a69e9556e91c3d2f05af16e74890dee567eebe3ac101a/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string82 = /975722db63d783f39f712552dbed318d5e4e7e4a68c5822ad44edf79ba0afd5b/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string83 = /9871de1742c1132c9b3171c4ae970e66b6ebe3a6cf31c35db881a32e33cc4016/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string84 = /98ba5fe44ef68256a7e5692d45f2ad434b64eece32859ce3723803f36a6e4d55/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string85 = /99eb1eb28b32a783c6619409988dc8fc70ecc9d1ebc05f286ec4c503d4853cbf/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string86 = /99ed8964fc153ac4984eb94f82bd51b2eda463d6483bb3e7e97d6d2b69b71196/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string87 = /9b8c27cbcbae9c1ec6fe4265c15a9122806b0b0bf9d1173c499d7d2ccb714e17/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string88 = /9c8b1aecaf1bdded80bec98ec5ab5b9b9754cbce9439dd9eacc7d1774d1438f8/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string89 = /9f229bb988451fb20a2a307f6d6e598822a8e9bfa69dcf4b31fd67a7f7f4d3ad/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string90 = /9f829612db928e5c7e7b08a9bf596b908d09c4f242b7454802e87dd2c2dc3f89/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string91 = /a1c31dc6e3e65461a52bb7f161f8c48e807ccd91d34f3382574d66314eac538d/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string92 = /a32362b2769cb3cd8caa10722c50208b7170fe82d3663e85425df416422b4d22/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string93 = /a6e07cccc0d66a5894500a057fe92440f1e372bda4856f148244ba369bf521de/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string94 = /a7db865b054314d253293a1f427d3a155da5164060804aac431020e26a40e1ad/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string95 = /af7b8e60b4b54f5f85e6b207ac51926cb076aa4319b8e4c72e59b98c85818cae/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string96 = /AutoHotkey\/AutoHotkey/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string97 = /AutoHotkeySC\.bin/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string98 = /AutoHotkeyx\.sln/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string99 = /AutoHotkeyx\.vcxproj/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string100 = /b04b1dc45652c59f82cecc30cf9aea76e5a1bd6cc3fecc450cef67cbcd825f06/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string101 = /b0943f704ffc3830b8b900408b94e7a27434602dd34e9a831f81730bee4631a2/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string102 = /b5a13819d673e09534661f3f1c2f85f4cac71f020b8a6a64586ba829e2cd3fd4/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string103 = /b75fa5157fd2ff049b07259fde91ab3605f737827fb64fcbc373e2bd1779bb5d/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string104 = /c\:\\debug_clipboard_formats\.txt/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string105 = /c36dd14fc322e1846a793797b758f5b0fb554f7f058da6a333c86f27cbf9ec01/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string106 = /c584ab8fbfa1702c36bab98e6e07b05585402ec00c2e44c245a9bd879ca049f0/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string107 = /d67778ebd40bff99e1f248b1612d64f70191632b64af60ea53403d2550f2d640/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string108 = /d71ba928d2755294ac049a66949606ee82e0e0a7bbb87760ae9fd1bcf24c0b8c/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string109 = /d7646ca3a26760fe5633288d79d7b6a44cfc19a85c5315f94e0861963f1c601e/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string110 = /dbf3490648efe876bd9a98d53e4d9110bf5e02a3914c0dd4b2a48db4a09799b5/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string111 = /dffda71c77c271cafc2f77aa007daea58f32a3562da3a3b924701117c058a336/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string112 = /e0e5f40f9ebdbdbb29d6084e448401335ae802bdfdbe3604abcabbb92baa0d35/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string113 = /e16e14a5902618298c24b6b6a2503d83d435bd647dcbdc2a20fa5f7285c57168/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string114 = /e27a87c132686f3e27675a53a2bce7c65328ac148ed2d7e11aefd657224d7d20/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string115 = /e51ba62ce6bfed434f3402945a9aa89f4b312076dfc597b5cae6f25ea0525bc8/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string116 = /e85105a9dafcfb10b38227ad4657d329e7ac579a19740e71e1a121919832c2a3/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string117 = /e9f3756f811224b3500981a136dae2ddd79987a510c9f389b67168a7fa494fa8/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string118 = /eac0df3ecfc829ba940a7323d21b688896758df43df086ed0e886c68d6003d22/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string119 = /f33996eaa68e8a7a5f5a6156b44af666049769bd021979a6ffb9abb29b45ea2b/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string120 = /f5d2887adeaa87f28d30174552b1ec976d302e7c804faa3e8ce74ddb0dda6c78/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string121 = /f815e34b79e1357b7defc86d467077293f56b4cac373394c01a66adabacf3350/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string122 = /f8b3dcc1c49da62b5302c64901e03eb6f15f0904fdf24e795bd8545e32d31604/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string123 = /f8c6eec28f90ec093e1b22cebe727abd2d408015f19944c9f2fea68d79a85673/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string124 = /f90226225d8c33b99efb6901942b695ca8e75d68a0ccf6000c1f0857b1b39251/ nocase ascii wide
        // Description: AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // Reference: https://github.com/AutoHotkey/AutoHotkey
        $string125 = /www\.autohotkey\.com\/download\// nocase ascii wide

    condition:
        any of them
}
