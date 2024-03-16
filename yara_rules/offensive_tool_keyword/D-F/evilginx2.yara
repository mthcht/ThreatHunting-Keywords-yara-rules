rule evilginx2
{
    meta:
        description = "Detection patterns for the tool 'evilginx2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilginx2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/Evilginx2-Phishlets
        $string1 = /\-\s\{phish_sub\:\s/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string2 = /\"Evilginx\sMastery\sCourse\"/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string3 = /\/evilginx2\.git/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string4 = /\/evilginx2\// nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string5 = /\/login\/e1837f4d\-1d0c\-49b8\-a242\-8f653226c137/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string6 = /\/phishlets\/example\.yaml/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string7 = /\/usr\/share\/evilginx/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string8 = /\/var\/log\/evilginx/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string9 = /\\evilginx2\\/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string10 = /\\phishlets\\example\.yaml/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string11 = /0675558d182096b75d100d91c77c1119d229c315f12bb86e353e49894b9e1d62/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string12 = /0bc38984ce64aa213a77c2c9125a68a057f76f354a44060f8342d5375368ef04/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string13 = /1827f84465eaa41ba584561ae108be14e693ba4c992e9d58ef0148959cc9efc1/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string14 = /1c267e901a65d142bf532bc0d26926dd9ceaa43e16b48df37c0739ba050a1c50/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string15 = /1c7e93ed2b3eed1303cc11d09b4fea4b183fb0e7041f9584c81ca4c989d8a46f/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string16 = /1dd63a324303ac18c64c435bf6acfff6efa419b20c305dddb9905cde41feeb4c/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string17 = /1de0d1e7805edcd36247e2c224aa8c691c774ba8497f88f2e2dea157c30906a9/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string18 = /1f7552f9d41f1e64d15e8cface42784b169d197992a072cf0072072dc640f58d/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string19 = /216361a2e00d7514c8300d3171dfd5cb8a5e6a061216125119a0d656d812de79/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string20 = /22379d69fa7ac3ae6679aba9a2346d5e66e819384641782e033f4a6efc4097c3/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string21 = /2443660c8c3e8fcf80e028c6417a0110fde1f3a0961f70ffb960cbf64958e244/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string22 = /2609239cc8bc517f684285133622e8b11192fb456e2dc2937aa2c6c2379a9d38/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string23 = /2711dda772bc1073c031d6044b5fe5eddc6943420ebd7e214e0b5e60adcd89d6/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string24 = /298047e6ce299b73ea411a8ed2d67484db6c8c276a299403e0b9766cc9079456/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string25 = /2d3ce0b49997314a863aa4a9ef25fe06021aac1107aaf63af18ba9730f13e7e3/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string26 = /2f2673bba488dc6bfd8e64f2d9b14049a4b495b7149a2e16980547467afc3fba/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string27 = /31795b2f772b6ad00274cc4eb40aaf81b5d38d6eeae56bace80a07bbb1aeac35/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string28 = /335ac01e952db33997b844a2e7c506d541e353d6e82ead3fde51e4879fde736a/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string29 = /3a3bd44b20afbb14ce14e70e474491383c2fcc87a554e4fbdc489c65ee7ace2a/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string30 = /3ccb81e184f94e47a9a7c7e75978ad9eda2850967b0a2e03a505776e4969b8a2/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string31 = /3d27ba8268164db337978538c6e6c33e0b91194d184e6b6b73f1089a425a60f5/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string32 = /43bc3fe471a81b11c2e59cd0fd55630cee7860f8caad44fb8ee54d109e01a5e5/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string33 = /4614a6da343623fc820d89d35b8c2a26fe69abf357af7ef7602e52808fbe8611/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string34 = /4aa27ae37edfbfe57f3ab989d192caf21b3c871516958eb77205c9ad700c3f67/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string35 = /520f529151f419ccb0e75d9f9d2c9a24fb4809468dbd95360e4483672db46407/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string36 = /52b1b3fa12706c1cc7ca2da321e23b151f812a5f7660f0114cc8470de3a3065d/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string37 = /55049f7690abbbb5c8dc844e54b63269d111c0cd21e98854c666a27788dc5de6/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string38 = /55a3bbb8a62578b455e478cb197aadd389f2e65418595e5df4636972be878710/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string39 = /5740d6067561fcd27239374abbfd7076d3df5909b107a32bbb2e9eec0e9f4d61/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string40 = /57630a0b38ad185ff8a8d0706ff9cebfd12f47526ceeeb90cc3a17e124316fe2/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string41 = /57f5a53203d19daa9bb094b442bc029a374686af5be71741e5536e35590e9f9c/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string42 = /5a2845a19dc310535eec5c74dd770db258e90160ea63e5cc9d97ab87de8081ff/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string43 = /5a3ae8d1bf88a4415c293623ca868e718bf2addbfc88953267bed9c9cf57c2ad/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string44 = /5ae17ceeb8dcfb5eb56fc27876c5047ddfebcb9114beb0a03db81000c46d7054/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string45 = /5c5bd260c00111edc55b4bc8a82d72e0a510f738ce3696ab2bbcd4a38a84bb12/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string46 = /5c78c058c8278438ce30b86b3ccda222410206ec0ea5727b93b74bb8c6748bd5/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string47 = /5d447208b1a06d45b5563f56da869e3c6ffa8e67247809798d24065d719160e8/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string48 = /5d494fc79356aeb1e983aab7188e729550c1f54ffcdcb02270acc492f2164afa/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string49 = /5d848352fb3ae2109dd1ee927717c8c004f2e07f33b14d7fd25dba71784f5579/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string50 = /5ebd789e726c94beb41e0934df6fb9bf62af28cc87093b9785dc9baa4ecde96b/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string51 = /613e5ca15d9bab3a0bad0c5eb8d63894c1b9fbab924385296c29d3b4f3479ee3/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string52 = /64853db4da2d13a82c795e1eb6e7e2c4efc2d673be34b5f65398f54b7277a5de/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string53 = /6522659bfa7046803bb28a749799fb9b876d656fa46037fe28709fb4ad15d115/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string54 = /6555c9310f7087fcf0b38eab5ad4efc6ec91566ff5bf2fbbed4e63c88611c395/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string55 = /65696f93bce6d78c8e377fc3c4c56123f49f26a621a332bc764c274aa7c81632/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string56 = /67831df0ff8ed3ffacc3678a5c4c09a3fcb755ffbfc110d6f1ff61fe65f31d28/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string57 = /69ee333eaf49be76d5bde1d3abfbd2e9a006a316284394e92aa71db1970d927d/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string58 = /6a5607a6886ad393bd1926b90a6364fb8b6546ad6963f42571c609279b446faa/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string59 = /7076e114583006ebcf8f50ab7540ce8552af788431ef2a89227e74876dd13e17/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string60 = /7148724805f706f8da206b24e03f2f6381bb9bc6959bbf51b6414ea8903caddd/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string61 = /72af248c9e2b92add20bde3532f73569fe2c3e941fd12c72f13696f6ccd60813/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string62 = /72dcd04c582db154eee02cde9a14312542b86615a88bf47d6529b26f8c87914c/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string63 = /75d0adaef55ce5b4670e7634d3f440e9d7e0eb1e04cb98c3919d0ad66dffbdfe/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string64 = /7612416d8bde145810923ed8f75d2c1fb81cdecc1aa7a997ae68cffb5dc99f43/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string65 = /7760d7ef318933db6b09dba08ec12ddf25ead0512c45bd914256c97470c4eb29/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string66 = /79816edc41cd5e2aeb19f0227e9cb9ab0b5abcc54931c6bf29813f8762828805/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string67 = /7a6baa66cbbfa32e37a003017e6a24ae5ba2764f39039a56d7556f2931824e49/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string68 = /7ce9ff1b4f75bf4289a2f1a1c33bef9719109712019989d28c14b51703b973fc/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string69 = /7fcc036a7fba571b7f2928f0a6a0e0838cb9e1a2a8231f9c30ce5baa144e8108/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string70 = /80\s253\s149\s118\s169\s176\s183\s169\s182\s184/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string71 = /80e5d08cc3b73bf1c8e1b9ad7280936bb8d83f0a41f6fdd277e19511e3340cf6/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string72 = /81c02fac6308e64ef8eba1bf4088b04daf1d33ac295c9a376b31e616cd3d4cec/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string73 = /823c3d2bbca46e7aedadfef6893babcbf14b0182e598a9ba958b84892daaeeb1/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string74 = /88113ededbda181be6c6f9bd4ba8145666b48bf9e9b8dc170e66e884b10fdc91/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string75 = /8a65c348023a1a5555beb0cde66891fd39dcbd8e6fc02c1ce2022ac2afe68a5e/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string76 = /8aac7bb51d605351a79f988d1b1772ae94d4b8ab4622118259effad125719e99/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string77 = /8d1f3e17106324aad99a98f5dd921db9d27a620b37cadc06a4c470f4404dfca2/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string78 = /91b1c7537e69ff7ade05c1c3a6051c2981a022a11b71c6e355891e294574a066/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string79 = /945efb5ef7d46cf1e4f5383fb158ea5cd63d42214ea44abd73592f6ceeb6cf33/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string80 = /9748cdfecb95fd7bb1706a566e79d3fccb1418bbb4307f7a7a1de1809db83afe/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string81 = /97499fbdae8e2c952f21da5834caf06b11dcc28d74b034b509bd174f3d1f1739/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string82 = /97e7f134cfbb11e0e3ade71cdb5de36ea8cfdffe5272ea7293e35bd2b91f3449/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string83 = /98fa9af535fd48260a65e18ceb9553187786742c6c77486bb27e5fe61758ea77/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string84 = /9d571b529b8c97f1d95d00147a98ca6a208446100108993377ef74f7bfab0ced/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string85 = /a16a8ed5999b3b90c7f5a7a80b7a55fe62941d3a1300ea8f0fcdd8550e93a947/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string86 = /a7a5c912263b0207145bd9c2397a4fa338ec82217df2ab83471bb884e473cc9e/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string87 = /aa14822e2f2acd7b8aff1ebf1f2e7e9f800f6089f868ec7464af6ac01d7f9b3c/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string88 = /aa5838415ca20f0b6fe7858f457f129cf442940b3d4676cd243575809e53988e/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string89 = /aeebbc6ea13dde53ffa47ec90eb80c571c81da63e36f2c8539a9924f54933a09/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/Evilginx2-Phishlets
        $string90 = /An0nUD4Y\/Evilginx2\-Phishlets/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string91 = /b18d778b4e4b6bf1fd5b2d790c941270145a6a6d/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string92 = /b89570294bb08b6ac4245fe0db6e35c1b23fa01ad3a9ac0bfe07043c7af3350c/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string93 = /b898e52e3799d4c3c4fa328c400ba620c814c11ca23d0b7ec2f3fd7917a7e8a1/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string94 = /bd78ea00b16797551d4f40297f42e9b1f9d912f416a115c3eb10f340246a9d54/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string95 = /bdcfb9b63fd01bdd50427f205338e26e8001015b4fe14b6016cfb08e37c08a6e/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string96 = /bdf7dee28fc21a09ae10d5e3a75e3a7713e705e78a40f55a4c003c9358174372/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string97 = /beb982a616c2c4cd716387b6a4c7a4b86ddcca0bc76faa94b4c5f10ed7abd592/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string98 = /build\/evilginx/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string99 = /c086c1e601dbde7b31cbaea56b915f22b1ebc21d744a431984406e6062b4b865/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string100 = /c6bd027f5269a980cd4deffcdbdab77eb317db2a9737d727b55fe37710cd2f95/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string101 = /c7ffb81b3cd5cfcfe18363f998cd64428423814d5a8713d89e7992941884587d/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string102 = /c923b2051d3e822e390e80c7e8d56f6b2cc62ae6688ca73745684b57154f3ecb/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string103 = /cb0a620a960506193df32016f825248dec7fe504d8b857ee54a88ad1bdf8d9ce/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string104 = /cb4a4a24fdd61493e58d83befacd93981771c5e8e7ff206b1c6050134613ae4a/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string105 = /cdb6b0d366c80ef521a59334a58f95ea5b7dbddc6e9f81ff28a11ec44ceba696/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string106 = /cf2f9d4e499c45cf102ede7ccb8e0e4e44005f9cf0313024771dda337bd6e1dd/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string107 = /core\/http_proxy\.go/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string108 = /d0659e8489bc633b617e86f4e7994a593ada5cfc8463f79631d9672623b79750/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string109 = /d546105ee91da0a53a26ed53f90414ea5f56a272caa137629125d018354f6b77/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string110 = /d5591f81fb5bd90d3af0954008ecfd433eeaf6ecc99941324747ca7433ae5985/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string111 = /d561756dd8152cceb60d50ae5650eedcdb022f306f193017aede737428ff2452/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string112 = /d9c7dc1a5a792486cc3853620eb700e26a047238ba92c757b4f9d40605dbd3b8/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string113 = /da2e2e4a0d34d63a452322f2fe5f57416aa79b6abb8a2a7cc3917a3b772d4cea/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string114 = /dc25fef1e036e80dbbf1a5665fa13dc1ed6f8c56875161608cdf532d8a21a4a5/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string115 = /ddb178cbaaab362c61d3d061b366625d205f208553ddf341b1c8fae466e5bd6f/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string116 = /e094dc2a9ec5fe9800948a640f416fe610fdf155874e897d3cba6cc86f854083/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string117 = /e0cc8936e11dcf4e016ff32f5a81aa15f352cb71ec8a24b383dc263e56425018/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string118 = /e3130262a4adfed3a225075d6eb93c5caeeba93b1253dc1b148f8a80c5c35a03/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string119 = /e62d0d5e71daca0aa1c2e899b0da9668167fcbd20060ef8c01a8d8b66f0a32b3/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string120 = /e988e9a36810fb0fa0fb32556cb93c8ea4117e4176402ff74e397bd4a4d125d6/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string121 = /ec57e5c4d592d1ad0a0e79b22e85f8173bcb3c03f4497957f90def4175ca383d/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string122 = /ed4d66eac260c54457ea1b9fa50be035dc89b32e7a318bff1296606413f25cbb/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string123 = /ef0602ea7c5cfe523cd58fbfb20f835a908c5d3873fcb14510a042d13de53863/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string124 = /evilginx\s\-p/ nocase ascii wide
        // Description: evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies. which in turn allows to bypass 2-factor authentication protection.This tool is a successor to Evilginx. released in 2017. which used a custom version of nginx HTTP server to provide man-in-the-middle functionality to act as a proxy between a browser and phished website. Present version is fully written in GO as a standalone application. which implements its own HTTP and DNS server. making it extremely easy to set up and use
        // Reference: https://github.com/kgretzky/evilginx2
        $string125 = /evilginx/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string126 = /evilginx\.exe/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string127 = /evilginx2/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/Evilginx2-Phishlets
        $string128 = /Evilginx2\-Phishlets/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string129 = /evilginx\-mastery/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string130 = /f5a5a21ee3a7dfaddae81cae7ef2df852cbfa44fdba51dfa0678a1c2d9d91c36/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string131 = /f90e3e0ba8b25e863b1d994d088376b2caedeed3b7bb5ee6c3f6e0e89bcaf023/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string132 = /fdb2a63af6a5ae9aa60ceceb9e928188ac793a89f5282ed44c0d4be5f79559bb/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string133 = /fdc984c09659c0ebf330d319bdebc772440dde7543aa6f74fd523a02fca2811d/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string134 = /fe8db7541bc0c9d05dbd2e44e5eaa2bfd5c79968983860416636ea2792abfa5e/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string135 = /ff0f7b3bceac2a15be7b35bc7c1933b46ba6eeca6bba97dbd5227b59b913cb26/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string136 = /ffa5514b45c48061e412487d4defdeffa87a338213aa1bc4aabb3259ce18d7aa/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string137 = /ffe1396fa56e5f86812443498cd6c8abfca613099df1261d08f06a73b14be042/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string138 = /kgretzky\/evilginx2/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string139 = /phishDomain\s\=\sphishDomain\s\+/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string140 = /TARGET\=evilginx/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/An0nUD4Y/evilginx2
        $string141 = /This\sis\sthe\smodified\smaintained\sversion\sof\sEvilginx2\.\sNo\sone\swill\sbe\sheld\sresponsible\sfor\syour\sactivities/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string142 = /this\.is\.not\.a\.phishing\.site\.evilsite\.com/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string143 = /X\-Evilginx/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string144 = /you\sneed\sto\sprovide\sthe\spath\sto\sdirectory\swhere\syour\sphishlets\sare\sstored\:/ nocase ascii wide

    condition:
        any of them
}
