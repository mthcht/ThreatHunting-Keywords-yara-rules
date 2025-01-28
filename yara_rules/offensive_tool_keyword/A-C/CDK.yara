rule CDK
{
    meta:
        description = "Detection patterns for the tool 'CDK' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CDK"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string1 = "/cdk_darwin_amd64"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string2 = "/cdk_linux_386"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string3 = "/cdk_linux_amd64"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string4 = "/cdk-fabric run reverse-shell"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string5 = "/cdk-fabric run shim-pwn"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string6 = /\/DockerPwn\.py/
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string7 = /\/linux\-exploit\-suggester\.sh/
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string8 = "/tmp/auto-priv-cgroup"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string9 = "/tmp/auto-priv-mountdir"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string10 = "/tmp/auto-shimpwn"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string11 = /\/tomcat\-RH\-root\.sh/
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string12 = "006c52fa111f12a54c8c543f5e7421f3841bae6d5a4e16054943a5aa5e9633b7"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string13 = "01feeebb7db49be46eb416caf2975ff62e79061c77e20430fb0d2df578b307c1"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string14 = "023fbd9f1d087ec3cb0761e01d95503f055e72209f85513380ed1b32177ef570"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string15 = "03c387fcf1090b813124a067e3434845c6242e7d6d4f0a835f78a96d6fb6f731"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string16 = "05776513007563031e633e1e5820914bfdcac5df19fe7fc93be680df32f75362"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string17 = "0674724cfc3997eacbac08e11b5b416a818b1dab5c6be50861babdbf84c376ad"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string18 = "06a4364e32aacbd0d0385b51fd849a72cd52e99964610c6a108ab2ac07603342"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string19 = "06a53f84d7e034e563a8fc3747000bcdc6b9945efd0ecbc990322ff527b3ad04"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string20 = "07c90800861a9cb41dd71f0af41af0ce1b174fccf71bf88abc6d82f0208b2d78"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string21 = "07d53bb25aaa1b6ed1de40f0b8999be20a399172e49876cac3600503793df581"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string22 = "080b84e655682e3b4cd130b009a6c838a4c96ea147796cf216ffe3ebbaa256b1"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string23 = "0857d4485dee17166c1754eb699e8e8e720bff825717e5a23531cd4b8a3c30c1"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string24 = "0956efa9072a03fddbe779da42e60df115e9d71bf9ac846ade8b751e4530b084"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string25 = "0976936c3c02be348ea926ce86c7204c7e9e59a092477e924c1a1d5bd97cfced"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string26 = "0b199cc96ae7a68fcd8236cd2f995347c02e8a3ac7311584f6ed87b3dd50cf65"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string27 = "0bb79f2fe4c5f6d451822a26cff27b172270bce29d7430e01bebe904cde0c215"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string28 = "0c9a9c3ce08d379b81646f92d8cb90fbd3fb384e497a4388f4bc33f1c4c41a44"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string29 = "0dc31dff0221a2907f19a6feff091161297598b7fab68a0272f7ce0d7698abff"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string30 = "0dcb0ef0bd6b1a018108265c2bd1acf0a34ac94f2fe012a3aea22a23b8a151c2"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string31 = "0dedf25f9bae707cb1cd5fc106f4516dc0ce7d8bf2114b50afeb6d2fbe506466"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string32 = "0e17084a14b6af8e50ae4917261546121279fd94299bea1f5fcaa77f18a0feaf"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string33 = "0e411f4a58f7ca4e77a39c810bd1cb44eca9f8cbae2a20d1c3ed6d3f1b9c4f81"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string34 = "0e8ad3e18880129b9042c97c891691f1437dd648a58480e0d4448a98718edbbf"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string35 = "0f45809e1a640a7f54dd5211aff1b5239c310b0e81ddfb1244345ce6ec9d72e2"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string36 = "11ae0608b6218b088dc3880ab366c93247bc33665a8a7f14b9da4d450e449dfe"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string37 = "131c1f2e3e3062392bece1caca144ef426920af8c8a54912f8ec23321a766b5a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string38 = "1392c9ae26021890c4fe0a3a960426da99e504d587b971408f40997d56e1ee63"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string39 = "139c41629e75329a9582b0a3ca07327a134860d4cc3686795a5fb69d09ee50aa"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string40 = "13e50600945f06df6bbbf28c06f76ad655acfbd866cdac2845fc48be282b7e6a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string41 = "13f42e004a25be9ba99aee3396a1d810026d7750d1e199774c5ba8410b15ae30"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string42 = "1416d3d651adeb29acbc825d7d537a379fdcb78102c36842a876dcf29e76c0e8"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string43 = "1731851bbacba1bb0339f252f84a8f170532eb6f82e024e25071ef889e24d936"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string44 = "17b096ff5df1b612abc12887e65fae97280533bfe058ce6becb9c0920f4d4c42"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string45 = "197c42343c75fbbb7d77f3aaa92e04e43ddec927887e889197db72fcff5e9df4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string46 = "1acd7ea1364e9c78d271cc8341ae804e8a6e143d4c31103d6dd5424dbc80498a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string47 = "1b2c21dd0c747782c5b23b0ca390a23a17cb3fe437021c5f44e5d77d6b71f656"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string48 = "1c8de7031ee8dbf83ffde0f1d6401dbc9d95059c984290b115bd58c20b86e8a6"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string49 = "1d2e4fa684a99e31479bcc0e5e14aa7f3c56cce3de71028241a9745c67ebf034"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string50 = "1d533c26001b29f11e09de0c350cab64faef97ea49a41f579d01b9ae74d2a0e9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string51 = "1e82c733ecbf30e06bfa200e327fad167e79a55854a198f92afa2fa7d0f9337f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string52 = "1ff183ed7b15612ef77d444187d44d2e1d76df09fa1762c24c54ab45440c77b9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string53 = "2058e248325daeca20f053bfeba403667aa6dd0b70b959963076ae8997c0cbe7"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string54 = "20f2e5e7e74953d37c5986b751d8d2e0cdd21d2275dfdfc21a5f4f8b4a37776f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string55 = "21582bab4103dda43821915b76e96870431e1f2f59bc0135ba4700008abdaa32"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string56 = "225ae3f948ca67c0f37ad69a5ce542c27c370993806599aeb927079bf8553acb"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string57 = "242a11999f0c5b776400f2462854ef1d07101bd1085e3b29c9b7ba825c93a3fb"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string58 = "2518c6ab5e78e0f644a5c406d84778eb45991564ba136c266d9696fc6996e8ef"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string59 = "254cf55fb776afbcf5ff93f9647303be1f8bee48bcb78f138881e4dc17c34b81"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string60 = "259c9c57a74382b07c0a630b3094489b3aca263504b4fda79d3c20027e2a74fa"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string61 = "28009247ff5f8ee93dcf3fa06e60eb43374eec61f816feb61081e2d53f4806be"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string62 = "28110f190791aa5b4ca3f0c36dfc39cda8716f165789599de34c8578a70357fd"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string63 = "295eb7f2a9039a3ef9552eda6ddeb1d442810621de623fd08a010514fe588d35"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string64 = "2a707260991123cf39ed723eaff4bf99db683ad35f58ad43c75c8fe2a5e9a4e7"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string65 = "2b92652d4909d39e12fc9320188f9e834b82f80d3aba92dea4267608f3543861"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string66 = "2bb27f59beed6f28e048b581de811a1443aa880dc8172f3156146c4cf782b68b"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string67 = "2c757f0065c167e633318ff8d43cb85cf936eae2db224f4e066098f4a8cb324a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string68 = "2c901d5da52c1766eb638b8d1b35a276121f0fb2a7156cb591b4f7ca054c1ed7"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string69 = "2dd16e2f18bd45ff80eb56a524d3af4e87f55054fdb3ada3d2a097824b6487ac"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string70 = "2eb30e2abc71fadaee5980bd89a8e4a2c95bcc5d60857a3c13b006c186307e8e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string71 = "313d2e2dad28703bf74b58c71131036e978667067d0cf77217435f10ff50a7df"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string72 = "31b9c5ce299981849c4ec0f90e6dac5a7b894c654eab1c3db4099744a5594e80"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string73 = "32cd84b8c8e4df09df5aaf0c310a954d18b2cc96aaea2ca524b79f381afd3e55"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string74 = "330253612d4c4a3791acfd82257d5a4c1e68ec989e0647abfa4baa560cf0a046"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string75 = "336b7dca10b75274a81c04cdba1989781ad742e968ebd41e5f901e66f106204c"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string76 = "347e7990aad2244990071b8b5648aeb675a7792b742ebbc08035c80c916702a4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string77 = "350189c879eb3d936a434927b1fa41d353d2ebdbc6589e9efa29ea5e05329fe5"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string78 = "356bdd6cb7c92146fcee5812aba9eb101ff713ff67768bafd59b6f33a5d61eae"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string79 = "35a4bba030e749de8667b0284982bd8d187a5ed9e1ced0b3c2e67136aa839cc7"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string80 = "364fcacd8b55d7d54162849b620cd83e9f50ddb3c7c08478f391cce09449b452"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string81 = "36d4c4959f8472bd2473abfc906db3c54d83ee71228c3c133d8aca97cd016d15"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string82 = "371226668baa95b330676a6268145ad25bfc28f59710f35fc1888aa6b70a74a4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string83 = "37bfb3819257d612a6dfed9954c9ba4a8da62f6967ec8221c802d7eb97723113"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string84 = "381448682cb5ea5ff1bc8bfd3462e637da0445fc74fdb60e0de5e11d8c2dc90d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string85 = "3897adf59fea097e79c69c0c4fa8961b9691232f382a52b7bee3ce234028da4e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string86 = "39f6d556d0567606d5763e60fecafeb3e5d16afd986c05602c06d2486d8d72c2"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string87 = "3a87a1096cb7cd4dfeb7d8725aec180b68c3aab9393f50ebf0431cc7189b6d20"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string88 = "3ca57afb3c9a3154212ad9f9eb323ce2cae89d046e5bf05acb5730a311e4e9f3"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string89 = "3dc271adc2565c38eda5fdaee3070bda8962159d17ba625467a0f3a6e5e440d0"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string90 = "3e1e22f3efa5aa2e7da26e2e6e82468e20de8d593b748f2521cfaf78d9043a2a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string91 = "3fc8aac43db6c83112f9bc168ae5a32f1cdd942376941341c621fa36bff26647"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string92 = "42e2d4b8d628e3df77baf23238076afb7003f1d31fb08032324f249d80df8302"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string93 = "48bf95a01c16f6af2c577d1e1df7e53225edbbfc2014b2ecec5f939e31a6c576"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string94 = "4a1e4478704d8ad1fbec9b3258f315028fedd0dfbf739508ab1438d42625cbef"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string95 = "4bd863af3ba70c958caf5b048ddd90a32a54bb9ae5d3e7578e8e0f1330a7d68f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string96 = "4bf92f0d8d8e73629d1e2b9f03375dbad214021e5a117e0557391526297c5314"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string97 = "4c4b0e00d9620697ba7ef9ff00fd58022b9e39db23dc65348fce5d3a321000e6"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string98 = "4c7260ac051907d12896054145fe103f9ea06de3bb2f04f0aab953dff32028de"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string99 = "4dd16113033905dbff69b134008cb848367c4d6899c6d5f9b63164328e576d79"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string100 = "4ed0631fabe9b3b097f314d1cddb565f082533bf589e8366ec01d149c931d6f6"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string101 = "4f188f89c92bb150c8b0b623d2041373b946a8920e97e464964ed79def029605"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string102 = "4f52fb4cf7dd744b01695e5356442182bc9fdb635da8f766537c12e0d83ad18f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string103 = "51093bb7f3a947ed390aa2a560dbe91621379ef2125582249a5769aa5a58b379"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string104 = "54e82ce2900876594c573f74437a23034f70f959e428bb2cf046afe73f6abc56"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string105 = "56ab5129d379ec39c8037a5937b4ce5cf6680377786548df125b93473e67623a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string106 = "575b267a045e31d3616cfdcc275c8bb6617136b1446253ee2954104b199276ff"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string107 = "5776b8a6c27e3375134e81fe72a0eebf781029ff5e05683fdc58459741a7c437"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string108 = "5866ad6e1eb1d3c5481179c4eae84fc733fca93782827f08b8e980dd455f8e1d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string109 = "588f790b5ea620a3077e6231bef7180951410f445c5d5b9aac8289b3a8d3cf1a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string110 = "58d9516f4e361b773e8638c802e7d0bcc716d1c750d7306764062394fc129983"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string111 = "58ec2f3cc5cbbcf8add01a0f5f7c8331d830b7944a1031788a5afe4a70ec0a3d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string112 = "594811dafdfb9f5cc56b604d8fe97777c23057e37803ec34afdf5680bf9276ea"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string113 = "5b313e80767783165c9f99079a6210582b5f57fe4c3f34ab2c5d27e6b1a09695"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string114 = "5d4d311ed2ab95bbd9698cbd26c83ce62ee9a665c462ef9f6fcee2406ab795c4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string115 = "5f62f9a20546e50fcb59aedca67b9fd9252c1c026ef81649bd9eb7366c4376aa"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string116 = "5ffd93d97e56861c46c562585d50dc820200763e633052b6a6d1e53566822cf8"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string117 = "6112fed1a30fcd45861afdbd13a6888f5cbeb6c3711d8262d6248eb4941aa2da"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string118 = "635640f232a519c71fbdd148bfef9ef8f9c61909106f2d458273fa07830b21ea"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string119 = "64b40a70b232b7e23a187a11c52ef8d8b7f3e16a5b869af16b390cbbe4aab935"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string120 = "64c86a12800b8d5064e7313a43eb6f5504a7043ab15c227cecfddaf84cc74ced"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string121 = "66f1e5e9916366d406955233a55d5bcff573c46a06c2424de65bc71adf6629fc"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string122 = "67544c3753cabf093153fc9fadf25640e8ab4fec6ce16ae37844b505c232fd72"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string123 = "67e7e9e8a9ae97ff4a2f1878746be4c10af64f43867d2e9ead31470145c689b8"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string124 = "68080b2cbfd4488f96e0c315ea7e8bf6204de010a05eeb2da621f78caa7254b9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string125 = "68a231b29bc22ff2f956bbfc0215f5c74880da394ddd484144a8ef1013c696d1"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string126 = "697320ded8b271c975f6ff97a43eb7bc444cbe8648b8c5f34aa7652e14893306"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string127 = "6bd11a9b68e81660518ccc9888cf6ea1f2d85c5bb33857f543298c2386e07bdf"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string128 = "6bfc3e0664e6aab7d6925ad1c191c75bc1f1f5b4dd4f8c073c5eef063ec92de7"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string129 = "6da016cefca0a050afb4c3dbf5e07f1af4fe69b24f1be45e56444fef537fd2b3"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string130 = "6e24ebb4b88122fe10261cb8cf32f92c812690c49aea29f2d708557ea5feb186"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string131 = "6efb691f0411b0e57b39c9efae1a55033cb8d5de3911d1ed120bf8787f395f1f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string132 = "72ce22f23461dffa813c1a36c37ae081664ee255cbaf0e4b87d5108ab3101df2"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string133 = "72f7e33c5313aa5ab15b99778b1f3c4d50d4710b171a635994d0d01e47e8173b"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string134 = "752c9bc83cd57649bece5f5885d921fa0dfd8cb62df66b6db1df281e51cdb560"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string135 = "762df2cf658c629e22e2f30827bd2b42de41749e2a387635db41849911641121"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string136 = "770e9e98e3ed07a224cbaf8fb78c5c9804b580f04470884cead4413616200621"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string137 = "78012b117e06baee37f32962d1dbd603b02231d7c4117c577765ecbc245842d6"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string138 = "784859b081e3bacd1c8c8a72374618f567cad2978835e241d9cc586c27c6d00e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string139 = "7abda12808ebda750211656c4a931ca9794121b42d2a0be50dee43b9fcc84718"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string140 = "7c48363688227e6857b0dec52273b450e3fbb108fbb5ca643265ba79ee1598c6"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string141 = "7fe4d08596fc13f16ed9bc29345a09a153e7e006bad88289836092bfc0e1ff1d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string142 = "802cc16a8b00b49fbc1685cdfa652fabe7b53d5d0e1fe1a1da4ab0da59ec263f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string143 = "828aede9a7bc193899b66e8c10ac10d24398cf79575e771d9a970d3f9a4cdd92"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string144 = "8432665ec509b2c4d2f2cac0ac44d543cf9991357071e3c0323e3b7e7741b038"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string145 = "86492637e46635ef72b4660016c2b3fdbb4c581b5f8dec1b6dc2dd8c04031e93"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string146 = "8861dd060f4b09113d6b8b10c213472d0ac3fe0f654724ec90fb5398ddf890e3"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string147 = "8880e4d7caf33e5da9a785d4c2da5bdcc6ba6315f882900f88c0adf1872e8fb8"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string148 = "8956389a7a50dcf4b7ab221c1b91172e7f7fb298dbf43a8251abfb76334e7a4e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string149 = "896b8d804debd233200375a5b7c1218d5b8bf5f53aaaa685b9d411c0770e27d4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string150 = "8b1b47c29bc124e99ea4e2d0b9d16ae4c8042b26f4592c46bcadb208dd780f76"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string151 = "8d3754efe45f18834003648a1e59e39b36675476e47db1c4e105cbe49ecf6105"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string152 = "8de962c37d5fd876e8b402dd86e334a6ab66b6fa8242a2c8eeef4b6d1d0457ec"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string153 = "9093453fbce7f48351fa3e6f57793f3dd20737780eb95d25c0b1643d372180f8"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string154 = "91cd0a590f86cbda8e33e5a4d90303f270ed6d17b8b36e50030f5a68beb7a704"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string155 = "924fb2bd1fe001f9eb62509a05546d1aaf97ebbfca73c75eb665a38b34559c4e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string156 = "9275c94ba6160e9de488089ba5e4df9f831aaa8a9e2dbe04d0c7ca7feb3a4cb8"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string157 = "9484ea212c59a9ada48f9f08204448eaf013891b7b722f9d111f4346f7f17a4c"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string158 = "954c9e0a1f8f731d410d27e525225760bf46f9df26d7fa63fac9cf848c1fea97"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string159 = "96a4fbd501eb610e8183699b4fe209dcc30952e86c0fac80ea5808addc3d30cb"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string160 = "99a0e78b14a0147999489e76b275e0a4503b03ed682cb382338a19472123b74d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string161 = "9a4d894cc0d020b03fbbf1ad8d147fc7a871a633fdc67497685a8b8d52b465e4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string162 = "9a53b903ad8a081200358238ad9d6a203f916f458024dd75cb04bb5063241d70"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string163 = "9b1bcec7eb978a3412a5ec172181074837f08f4f9c256e8d9f6a8d7d2ce34d74"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string164 = "9b1c4a631b0c723cdecfc294363b8d10a969dcd3baaf9045ec1fb775f289148b"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string165 = "9c83d11868c8107f59440b4a1a5a7d1b0283be01781291a3ff5b22760340c11e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string166 = "9e8a97e342f21509bdba9c4abfdefafe5b3a4fc60c046415ad397eca356e5d04"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string167 = "9ea746441ab9d38f81e10c8688f8420a15127684c68cdf82ab87cf1e98cca47e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string168 = "9ed6afef63c00c3c4d2eb6003922a872f0125639201fdf2f04ce3ab3b991d2be"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string169 = "9ee370e295cb26ad1b06650144941dc380888d48e0c1ae446cdae7e00e055e82"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string170 = "9ef20604a95558331dc4bed09434f69c6b18f2916ed27245fe77742aafaa2e77"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string171 = "9f299bf02ff7ee91ee018f04d40911db1d133bca6a38d3bf318ef9e51e91f71e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string172 = "9f63e35d7b9d0814ad9f0ef23b89deb4f823d3b07bcd33df9abc5b957bb8be0f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string173 = "9fd9e9bb045670d564e0922020d56e56621b2710de01b683015accc2ddf977bf"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string174 = "a17dd521d044342b7866e4175f839e1418997d8143db358f6c6349ffb144e5e9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string175 = "a2041f36d6034a45beb519ff59fba80d6e7f6d0225b4123008d0dced4d8d6d87"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string176 = "a20e531b0117f484e0b2aa0debccc8edc597fbaf43578cc1c862eb98fb6a849d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string177 = "a37e4ee0bb7651669d595d3bb44edd135f9d696648f36fb9e35af1e84ee6b795"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string178 = "a3995533605772461060559d6afae9de2726e86ef45a53bb924792fbe9baa325"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string179 = "a41520ae22cf2f079517745389a21e9f90df6376fb61bc4243808f8e494f08b1"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string180 = "a41c1b9b2b36e65dc1d8f57a08165289f44ed287893c18146fa32953bc2949fe"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string181 = "a53d0d8ca3a89a4e43ea2993031c375499cc01810dc18c65097993c43cc03ea9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string182 = "a89e428291b7d4d870e2f24564c86bdaed721131926eeae10602c5b86295466c"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string183 = "a92179596d5d8b12a7b090485c96d00dc9f405246a1992b6ebd059a00c69dad7"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string184 = "a9f51500eba6088cde85a398ebe8d14f4fb52a931f9988049ab7e14570f39498"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string185 = "aa862e916af73e90f28c1407d5a411121cb33eeee5bf1bd2f130887b3dbdfd7f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string186 = "acc8594a9f95436e4e4a79fda6e54afad42acc212baaa52b442a161f115379d0"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string187 = "ae96f988b56a4ae501aa125e99d11308714290e287a21f97a4116b2bd9964079"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string188 = "aedb680859401bdea82e17109b9d6bb7ec6cfc26bf20687c14eea15c616efb52"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string189 = "af751c690671ffc0da6380ef94a25df3dfc5911c448319f7f6b90df55cca7b7d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string190 = "b074de2206cbff42293870201e0faf2113986a64fba6cc4682e2a87f518ee7d4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string191 = "b18a6f563afe5afa141713e2a569de7faac174adef1d3fa467a44d7cd8598a8a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string192 = "b260abb5986b96cb9308722a27d6172313cacdcd16d6f8d6a00867bf095dcf44"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string193 = "b2e2d49036ddaebaab3cbcd26b3d1742fca27ce42926f2fbb10791ce8af6f2a6"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string194 = "b45f9a6c21f34801656affa29c1633288fe44f859a120c3e1a69d3880ce4f617"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string195 = "b5c59b19f4a9301c29b40a6565a3c21dc71fd3baf14a755c67ca735b3d18cb9e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string196 = "b5fb2c18b9720d0bfc5f0d25a9922b6f0b88230e1005664885391ef140d7d489"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string197 = "b6ef9851d887120994e19521814b994f750f0eac77ddc2ae60efd75ad085b02f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string198 = "b6fb74cf4bcf1ad06bc0424af481dff96e98cf06803d450c4d9a3b621b63966e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string199 = "b75d4f2cb82be9e774f78020bb86d8df9a8eeb6ceac18b823c4c6459a3ca7faf"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string200 = "b92a34dfe966a9540d853cb5762574e659a33f965b532e453f5f0a2619505096"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string201 = "b9f0a5f6d8d717f469a530d9796bece42e455e201da01012c717098f0cac53d5"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string202 = "ba69953f7e76cb9a1d4992fbb7db913284d265e7d32f6659dd3527874a473404"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string203 = "bb6ca78dc8a3774eb3db52580c52bc6b47ca885d9881f5cb422c915ca2c2a7a9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string204 = "bbae26473d5ca41404788c5b58ab495e9b7fdd988986657be0e0505400047207"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string205 = "bca1f1c7d9253bafb3442c4dd95a0b18a82be404ab9442a373b2ff91a47f5164"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string206 = "bd3e5f1a848ec10158f529073a346f56c08a18c1e4cbfa1a85714037fe1561fe"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string207 = "beafc9e9d828c755348ee00e6afbcfa79072741353a8509881e13da012a27509"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string208 = "bf07c8fc6c899e793274614b8a98565fbedba9516c437c7594fec9fa15dd4d41"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string209 = "bf436bdcf33e8567d57edad7e673c9bcf6b4eb9a514d95c94a85418e964e4f8d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string210 = "c02322e9bf5f1a0655cdaf316371f91257b9008d2ee6dde791bac5e8b2e5064d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string211 = "c042f360a6deff1b41405dd0f5bee637fc8242d585c714410084ef068a90d9fc"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string212 = "c142ea52e700259405c0de3aae652fcbbe9d476ca40aafb4309c60538d03f6a0"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string213 = "c2656885d23a89c0ce5ecb131762889fe7c39ff2cf4a8b6d8db2c9d782fb94bd"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string214 = "c346565a022b0f0c4957c33226e8b7a3d3359f8da8eeb97e60b50d6d3e1dea79"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string215 = "c417429bfef774a5aad6d5a745b741f291fc0bd1b48514bfd4fbca9345e43384"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string216 = "c52ebc7882d730dcd1d32551e8ed3eca5997f56079efb92c591e62292d3c0c09"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string217 = "c5e6f5bd9b5c828645a7c77f07a4a5973a3904d2a9ae01b2cb0ad2574bf2c8d9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string218 = "c68ea57d7555c49ef4c5ea05363fe0ced7978e751331ea949005d70fff000a00"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string219 = "c6986103a201b81ebf196dd945c4bf5b1992b4fd8db03479d7be2595a5c467fc"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string220 = "c6b8be2b81f56a9f4330f7ccae161bda9de8deaf375bb8d1150264aa6fb502e9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string221 = "c8664d51b579d5922ab8325a777048d8d661baf2767744829becb979784f76d9"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string222 = "c9203ada65ee8c0c96d177343c3ae42592f4486e5ef05bce0dab3108e9935862"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string223 = "ca6d09368c87c863029065d8d134bea7edefe73e270b599336185bec60dc68ab"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string224 = "cbfe1884821d8aa5cb10a0eec8719f8273b5a65f2ae826c7079006fff71f14e7"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string225 = "cca9d8bb94c36f2e971f834b980801d3fefd23fd8a25852867bb1be94d116963"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string226 = "ccbc5c84af4045835e6b001cdf845d63802e081cbb97d9625c12d8d0f9b6f852"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string227 = "cdac5cd3d0ff424315da3e233a79f72663c26e53fc4ac2e5031ea08154630514"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string228 = "cdf9041ba0603c7d7452a2866eee0eaa115ad5d8488d92c1c388c36d321301b1"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string229 = "CDK auto exploit via K8s backdoor daemonset" nocase ascii wide
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string230 = /cdk\srun\smount\-cgroup\s.{0,1000}shell\-cmd\-payloads/
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string231 = /cdk\-fabric\srun\sservice\-probe\s127\.0\.0\.1/
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string232 = "cdk-team/CDK"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string233 = "cf649763c47c27458c5af325697d002c0768efb7b45e5a0246d529519df56ea4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string234 = "d0315c0ae104a656d1b6787f8929a324193f65935b54514107f9ddb7639784d3"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string235 = "d049e53c682c148dc71b1a794973ad8c782014f9f32836c72ad141d05d94f022"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string236 = "d0a793ba054cb2ce81173cdfed434c511aec8c631a3597d9581c191bc1525c2e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string237 = "d1028ca3bb682ecbf66fcad2425aa322cf5214f6e123a145695047a03ec762a2"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string238 = "d1d106fb03d4ce0018b4a6fe470cf3e9f5428de54f9e3cfeb3b7a20be498869f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string239 = "d2053465e2b96e8fb144090dd3cb1b7d02c1364f0d66eae234995c89c2f57c64"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string240 = "d29a6e6ff589b020cadb8f8815eafd2a1a6224a1e042e6649c9747e924048dcb"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string241 = "d3d1a4bc05989627fc32615a0ec5b280f521577437a7bbce5dbd2e06a9a54602"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string242 = "d57859e45a603966302841da3a61fa3e604a2ddd7be8bb2f1feb9bde74464061"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string243 = "d5c8e759b790c6ffb3134c8f0aae5865e2ae4c672dc09eaa312bc928fd0d78bd"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string244 = "d650309e0c7cefdb0fd5c2f29e30282d0d2f1be44fc389158c5d011a987245b4"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string245 = "d697ea397da7603417baaf232512864bd8ecedde47dd199c2d32f653619f0f3b"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string246 = "d7020b26924bfcef8d88089ad6f9f496cc9b39ed08ffaf3ae857703ae154c198"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string247 = "d7f0690e41786270f345ff4851fd4b239631d4c1e7a6b9f74ad139565cbdb2ed"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string248 = "d83164f00776f7b9b32b840d6c7637d3af55fd19eaa351075e98e1cdfc43bf25"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string249 = "d836bdb64f2112e1fff1080145cd2f349478ba67e1d68bdfd9e734b114f7627d"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string250 = "d98fe823414e86c47619bc51a10d542d5be44ab64387e578ba4c21bf8cef9e15"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string251 = "db192e3adff9cfb3777dc44fbe037aee648af60c203832d7a5f7ac41e265f01b"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string252 = "db2c660c7cdfb86957e95790e3bef0a7ebf7fc1b1d7e48b14cbf70210ca87210"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string253 = "db32aad6f38b4b0b38b65ba962eb9c256640324f01cef1d9e9eda4a32106a8a5"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string254 = "dbbe29d4095a98dbfc4e2ef1a26e0696f75930a04a274a2a207c0bd0296b7a24"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string255 = "dbeab309b7ecd219233a56c43b0c95f88a39c7d1d524d5f71d319a5928a2b5ad"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string256 = "ddf4573b4c5fdfd92657979d79b8d8c7658dbb36e9a794628438ff01d7cca1a5"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string257 = "de0be23b564e470725a91e72bf431667ab1d2d4e8cb318a1c18e66b3ba97340e"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string258 = "de961474a71ea2f05fd9e9d6b862397660ed559533534bffa03cf9f2f2b70dab"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string259 = "e01fee07234e35d11957d7ff65a5e2e7e0bac4a4ff061fd5b5d90a42701c1c49"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string260 = "e0c9c27432a110f23a520ee1dad769a42f933062041df41cf88597fce97df008"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string261 = "e2c267e1e289e975e1a4a2acf13f30eb04dbb4a4da24daae02c248dbb199e919"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string262 = "e2e3e51ea97a2c74d1b98618143d69acfcdbbabd0d33607cb475757e05fc6c4b"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string263 = "e30443b3f19aafa06b3edb124228f6ac35aa51737c3eb78fa007ffdce9d75bc5"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string264 = "e3b434dad7f4330a5402271014b6a450ecf998aa10d66c640798d5b1d057639a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string265 = "e443f79a4b00598ac5a5adc8826b605db24b6345ae1fb4180aa4f173152fffc0"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string266 = "e4f24bd9724afff4200cf4c57eeb2ba37b9bf99b7add53ce1262e2e98c80a812"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string267 = "e8eb686267d1017f0c044f8725a91d2a3b0111156975f4918c9b3839b571483f"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string268 = "eaa6c3fcb9e722d690183ae349ac2ca935aa9bcd2942f6f103fd8eb842dc5168"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string269 = "eaabe990e3dfa97bc3ffdd9f7369553597fb1686dbd91e164560ee476e1d6e79"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string270 = "eae7c7548d28517d099afef1bc7664f098bfa3c533ee5a0cf763ab28480ebeeb"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string271 = "ebab27736848eb90409384d231b939702ce97482cc231aba7d0acf58e02db438"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string272 = "eca140e2de5725eeaa29ab48f86e1745ef0232aaafd04298eccb742e1241171b"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string273 = "ecfd0cd8274471f448e0ca1f0ee3d94affb9508c6c3cf8c72ade2e0fdd1b85b3"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string274 = "edfc7e6329aeeb8cb0df8734ad9083840020e9d2d81d4ae71609dc7339552a0a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string275 = "eec9b210d157d0ef16e7238c21bf66c6dd4806471853c3e976927f7be14ab918"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string276 = "f0c4face818f1c021228c140e453fc43b214141ed0273bce57be44cae6461bb2"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string277 = "f0fc4517a1a74f1922e41886cc4584c7683f7726111e40f03b26edc6bd9c6642"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string278 = "f116626cb8bd2787d19bbb0dbf578cbd09093e19ab27911beb1f61d46abb3845"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string279 = "f118a70fa7b02b858bb4fffb96d9a861e4b02f62df054a0d69854449682c8f85"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string280 = "f13668c26c13b4e0a8a56ffbc758331f311bcb033c1c74b1711a2258d6ed2e22"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string281 = "f1a3a780227dec46aa938096d1a8d8f6240e711d757a25aaec0f6c6adf0a495a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string282 = "f38ff305cbb6d9d05b5285fba66bb37817e13986ec3b61acf190b9fd3d903e82"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string283 = "f4e3039aaa1670e865d77746b6facb72dd3f72d8b240a972a6d48611b0ff4219"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string284 = "f4f23d5b522d8f58e46963452ce15087bcff3955bbea95306e24433dfeacbd3a"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string285 = "f5b77a3b40d262907ae6c65822622a5d9852fcba0251b9ddc391e8e896ffec2b"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string286 = "f889cf4f3cf56e385114be1e91477a51f5022cafb7bcd5cfc8eb20704e82e9e0"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string287 = "f930268ff8e01585865f3190c10570175b0ef11c1b17172c93b413df8507bcbe"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string288 = "fa7433173643095d5266fd465f88de45d6d157d72dc5915ab1334c03af63b4ba"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string289 = "fb88b7cf0b5a1136829a3cf1c25f536713e6d7033c8b95cf31ea1e1c14c33a55"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string290 = "fb8e1c7fbb5f253cffd87b965e587b4cb611ca2e5a38a13db70a082d8b8fe49c"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string291 = "fbebaaf3a90be35d2e00d1edf45b98799357f9321ff1b94ccfd2a22e44203052"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string292 = "fde15f9ac15ce720fff310f70bf5d36843516dbda4d98c9bfbcdec6ce44f28e8"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string293 = "fe43248d33a0e7bd20c619186b757febef4508bea3787671d3ecc95ed742b729"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string294 = "ff6240c57ec7aa0a28920a304f953beec996bed301920240228e696a1810edb0"
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string295 = /install\s\-y\snetcat\;\scat\s\/run\/secrets\/kubernetes\.io\/serviceaccount\/token\s\|\snc\s/
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string296 = /run\smount\-cgroup\s\\"sh\s\-i\s.{0,1000}\s\/dev\/tcp\//
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string297 = /tomcat\-rootprivesc\-deb\.sh/
        // Description: CDK is an open-sourced container penetration toolkit
        // Reference: https://github.com/cdk-team/CDK
        $string298 = "touch /tmp/shim-pwn-success"

    condition:
        any of them
}
