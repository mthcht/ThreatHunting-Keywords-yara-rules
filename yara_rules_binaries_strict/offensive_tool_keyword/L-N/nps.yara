rule nps
{
    meta:
        description = "Detection patterns for the tool 'nps' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nps"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string1 = /\.\/nps\sinstall\s/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string2 = /\/etc\/nps\/conf\// nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string3 = /\/nps\/releases\/download\// nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string4 = /\\npc\.exe\s\?\-server\=/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string5 = /\\npc\.exe\sstart/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string6 = /\\nps\.exe\sinstall/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string7 = /\\nps\.exe\sstart/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string8 = /\\Program\sFiles\\nps\\/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string9 = /0254ddc9bb3533d56c1e0643d587088624faf2bf8eb4dd8f6d37c963cca75205/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string10 = /02fef76d10ce6799f315ed249098a327b978b8967474a2ad03b5c359b5738237/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string11 = /03008e06f61a8a9404a216695d55edf3ee6f021231069968dd08de1a492030ab/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string12 = /031d71c5e90e9efeecb4a1163846c69ef42e8af0f0945914b079b58f6da038c8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string13 = /05e4989bc256f214bcefda8e830675356a7aae0944fe114c7c4823c51f7cf2f2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string14 = /074d726bf6cee59fe07d6f479b5f703fe423c17aca1bb047ce76459a24cf9916/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string15 = /07ec4fa926a9f4a90971f5bf78948fe4da7c6c4fc7c30d155d3c69c86258dcac/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string16 = /08390cf5db68b7171650673f4214c9eee385d94c302c202a7de39d9fe0182796/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string17 = /08854cc16c9fa4e9c61fccf8ae992e2645e59cb7e0c45d399775208f4aae60d5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string18 = /09104e5185bde84d4d5043b07bf067e190fa541ed07dfe23a8374adab15f1969/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string19 = /09bbcb9f2fd54e7a14b71beebb6a69127a422c17a43838a0e1bfcba45813620e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string20 = /0c1bb8a937aea9a05ec6524c92bf16f3387a52b94ec2ece27e2d98e1ee9fa721/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string21 = /0e4d9ac31eb73e737d91d48b2c1a461798bf1773775e32a7bc508d3ed2460145/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string22 = /0e83bafb7d54823e22c5fa5ff502924afb30c090471dcb9ba1c454b62ed5ca55/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string23 = /0ee13a1dc80aea39fb3306a3989be1fd14975cdad77b5e470946473e2024f4b0/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string24 = /1138a233a5a8d32e0731281ff9acedc0d930998a243d3fe11151cbc226ceb5af/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string25 = /12019e8fbf5e9de4d96c87be2e5e160fc2e51faef14a3fe68561523858ab6511/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string26 = /1227072f7b3532300b6c991a88b1faaa472cd0cc214d0c2b5f2ae3dec5c2f922/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string27 = /1256b5cd8907a87eaeb5990075115f93058f4779f348718f7ebf3958a006ecdf/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string28 = /125dadd033118d08acc7a70074c1174e99353c1634083609a27c11d7a4131a56/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string29 = /128cbad77f003d2c34c42041a88e628de1abcbc3ba0c2e6aa3e886a2d0bec83c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string30 = /132d0b0131489f45673dc3eb4c226f31c08faebfbbcbdce3b77fc07ea9ca12cd/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string31 = /146c1dbd6fc6758d9adbda9490b8272de6aeec711bafd925ad4057c3a2c317c1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string32 = /14cb65175994e6e27ef631df1e99744308197f80c84d86ea457dd98a1d89f608/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string33 = /15a22b4600d84490ed569c288896a53aa802a0ed466c8802debde5857fa20881/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string34 = /15d2be7e3c1c5edec59861a2989f2d1df2f77a12d75eedfa997bec5a779f4c39/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string35 = /1651b1dcc9a0a8b4cadc099992771c12ddfaadba0007a80d4c501f63890f0d9a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string36 = /16ed8368d7cfd8a298d59ebb123c5724fa3c8f04097e6993aa06b32aab41b263/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string37 = /196581c3cefce544c150faf2fb0ed7d82940adac5f2a5b51e034453644f725c6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string38 = /19729c5e11a7925f7b9ede557e6acf71da961f0a609e72b1f2f836e5f40533e3/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string39 = /19e2bd43425bcc1602df3db4fbd0775a29d70d24ae5ff139a1fefcfecdd79e40/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string40 = /1a3d0a8e65633283bb4e116282eaa271027dae9fb3b3658918198bbec4dd6b94/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string41 = /1b505dc8b0d60061082cb43caa8bc7af56f1b2a5064bc0040f4963b0735004ed/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string42 = /1bc86ec82025ba921af42a51e67f9e273a9a9628778477ad7e28b86f8b3326fb/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string43 = /1d1d8b1b9afd3d323cd82131faccddc5565475751c9e8e2b5d6bad2f5f387b42/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string44 = /1d3ac5240766338d781a6a0820e6bcec4db675910ce4bb2b1a96d45e71cf2495/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string45 = /1dd570b9672796c8062a8871e279870508d3c04e213c4f379dbe625216d310a6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string46 = /1e8a611cf3a7ef7c4450f7d514fa940ae996df29c2ddfc2a8195f53834c14d05/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string47 = /1ec9f1961250dc8bd691d8c30c29cf96601fd0244cfa385e7f7f8e4bc0886b02/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string48 = /1f0d9cbab0c3d005348e0114cf5b3695ec49e888a9ec20d5a0467b6bc257f683/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string49 = /1f6ecaca9176f820ea33f658c34cfcce3d33cb669c8a9184b4fb431ee791f7a2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string50 = /1f7d9978478d481767a5c0a2aee4cee9a57d52c4453ec208869ef4def523e676/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string51 = /1fac4f23feef2cd992baa85443ed71ea2fbdfc93c602719ae6b60b2e67318ec5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string52 = /1fad05fba304c7d47366a1737745df64437909decdd85ca8aeab97a9ff55d056/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string53 = /205557c0c8ffb366e94a954b35e848ea7e6ad72ed1f014e65a433288431f479c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string54 = /22ebd5b1976f3135b19ba715edef95821cf7990bb2670f2359f0137bc01f35ac/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string55 = /23bdd25637e6945b0c825452e40d52f4c327f30f99fd609b71e6c6308c6a5622/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string56 = /23be181e368fdf883f49f13e1ff704c2763a6b08dc1206985408b8e428440049/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string57 = /2504c2d20454d5caf5a0e24b497a3913c3289042b7fdf6bc336a25430085bc98/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string58 = /25a03e663d0f5d7212ecc343b491f4985a3592126df446f42fc09c445dc163dd/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string59 = /268bd4cf2215cfb4153bc7431f22bcf7d4a7790f305c21327566e6758fe3eb5a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string60 = /27dca74d091f98b35dd158f7060e06b7020068448c731a40b6c2bf98d7c4f2d8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string61 = /283baf6fffaad806ac328d750ff3014c917378455b54d58d0ba9252a502f8dff/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string62 = /29be39614ae599a05f63c98c9d0c357869318adf49136dbbbeb51f04ab1ff62b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string63 = /2d90f3530da1d697231e3a82df8a94b062676960dd7d32e0899c027cdf66350c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string64 = /2dba6fb126f4bdfc67fffd404746fe0dd38fc3fe7c72f97360df57b60e33155d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string65 = /2de3001b8720ed2ad3f7f25685172277a7032ddc098d2037860b4a067c0ba668/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string66 = /2ee991b61ed7a2831541079d85b4048128f5964ad70f03940365ad4607cc2da9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string67 = /2efa21402a699dfc1777d30a71a6532c6188ba867088d8e50ae3bfbeb873992c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string68 = /2f07406d517a0f5b8b4e46ecb1ef412924abf1bd43c451ed324f5a23e2d9e2de/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string69 = /2f270dfe3ae3f96ea722d7a164f048f7501031664db91bb799e44c13856aa86e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string70 = /2fc4590134d1420bbac69beeed06c448f185b59c2856781966b33d7d6fda78e3/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string71 = /2fd282cb4a91d1d4f3203bb55965efd86e8fecabf8594a3cd785552b6369eb7f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string72 = /318de1de99b98b45fc0af84a0ee30ae88e3d3b44016e460696b1b095525ba382/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string73 = /31a854dd758df379bdccbc630737a0e81e7f751e8dfa9d6d18e27a415add3c85/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string74 = /32a194633e4fb7143e68bdc59a8b1688819b286ea17a069605728bcf08fd357b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string75 = /335203012039eb31e583004d1d19b67bb296425e600fc4e575eda033a655a107/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string76 = /3397fa7a9770b48fc268eae7a8f8f7f01a7f68c965727a35b85c9128fbe3b835/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string77 = /33c6f02299b0000508619734f88c1c8bb0c8edf302efbd55c146e9a59aad4424/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string78 = /33cc5cb674c4c4a7aa6a724b980e9e8f9d918f605ac892628da6ba6230423f3c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string79 = /345fc62946d3c63291d8213af4a8a757387754424cc01aa55db6334995286059/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string80 = /3474e3348216b672c72d7a5c0cb32103c82ab2b5f7deb9a48a566f95361a0ac5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string81 = /34ee072372eb349c9e9acd137aa265eb1c3f9b4206c172b5e8deaff5b3dd90c9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string82 = /34fd5e0317fa3aa3439dd42857c889f12bda61055404058c08d8f40a3520d201/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string83 = /39d3fecfab8b7ea9d5a3f3dbe26b78a8d3bd6d1f191992faeaf70ca4954fdd0d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string84 = /3b40063cfd6244dbed0690aefe5a81f7b089677239237bfe8536eaa548c8b997/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string85 = /3bc3143560646803229345fded4a48e904c9e5d1a446c7f9163d7e0010e5dda5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string86 = /3c27eb99e32086b700d73f8153e53bc24ba62f08936b1be36b6611c5704a067a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string87 = /3c3361267404dc1dc47eaac52cd347c8c4a408f0ca3bf2da2ffb9152a85a1555/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string88 = /3c36e9e5780af17be16e0326c606e466f39cc9a736c3ecb2e8e965d00c9b56d0/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string89 = /3c4e36ce4e07e00a125f6ed01fc6797bac0c7e5ef415b4af08ca024dbb8af7de/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string90 = /3cda8f83a369ed200d702d90fad07f1d6ea719a876367ce0d7629b7ad2dfec05/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string91 = /3cfff321b41acc3cdf87f4e112d201a3b2a4708dc370a97f7eaed419c258f206/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string92 = /3e5f5be55582286c2411062a932d31f3c5b6d489c6e2927525bef92c34083e89/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string93 = /3ea8d03618c5dfaf31713be63196e0d2dfba5efbd2e6c6dc1787c6a2c0a41965/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string94 = /3f3804de2f7ecc0b5f86d3b136512c35788c8f0933fffbd11a2350f90084106d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string95 = /3f6a6c6beb96c55ae02199bf8ca34d317596dddab33ef5e1f1d129e4d8d36446/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string96 = /402e331588a371ded43b86c96e5d4424d59ad080094401b8c4fc87bb3b26905b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string97 = /40365cfc8131302172edbbf08c64f014f8dec760d487e8fe9bbf17141048a7c7/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string98 = /40b8524cf1b5da1d34f75b27ab5c931cc576e8bd1bf78ea587e4b652d843ad89/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string99 = /41794cd59707f4a17fe5736b0960fdd447d5ac35b75d70beb35c71e199b29111/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string100 = /4201ced96159133a8d586be95533b285798a60e2ebd6cc3f391be1eb91c83fa2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string101 = /42a8c91d6435ea450e9ad759489c603dd7ec731a28eb736ec818a21a964a2fee/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string102 = /4323e08164a3e0249f03d697dd22398b7ce185879581a4fc23588bb9a4d50ae6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string103 = /437fe49b059cae6e3fa58e998cc73d10c309fe76c0c2ce6e49e936589dcfd474/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string104 = /43a56d6c2de9c58277b8b10b2ad348d2b18b7d440ebf12b3c3c7099fcd06d9e7/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string105 = /446bfa3d1953383cc10abbd6e49cc3c27eeb76abca0839c970b539f69ad26c1a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string106 = /4551264b08c24e9acf8b38695d3334c9870c5b5a7f88b3d3a69d8eed0b6c927f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string107 = /472ff356009e3d68bdf619c87f27fd79f791f0245c78b553e6726e59817511c5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string108 = /4768435dcfd9ec06377e5b83489898683c97b1a44ec11ef452c640c82b48bfe1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string109 = /47a09946abb82f902d44af7c47877cb53e146d37d3701ae6b1afec149737311a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string110 = /48a1d2dcff404b6c3b2ab326d85789a29590a1efefe9a1bc2f5b973c39b9ad46/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string111 = /491d380503b718a363fa4ecc7385c501b12d15369b4a23e55f7fec9306bfb716/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string112 = /49a3e7cc6f7f1a31d5b77a8772ffdc6c25eb1ce35fa0c3de6e55149494496491/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string113 = /49bf39a5611a385ee3e498cb43bcbb7ece41b689edafc556f35826f538580d46/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string114 = /4bea75105d616920248cea812e818c2b103b786e050ebc27394aba87fdaca5d4/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string115 = /4e11543f50b3c5b039a4717efddbcf89d8c4b7e8f85f257ad4b0749c7d589d38/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string116 = /4e661f7632fefee0728e6c32d0ee6e738f7e6eb5fdba08b8cf9f8a65cbc4f6cd/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string117 = /50662415d68f78b67b116ea7f19ab8024bfa6fae117182488e53bf88fef2638a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string118 = /50c8a6e0117fd0a8c8fddb948e91c8488d67782c2975f4d7f9f87ff9a528b377/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string119 = /515e62ccd2de0b47bce74fd7a039ca47390fee162eddec6b633bbc1a26662a86/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string120 = /519ee1d48987fae9cd561d0b1c6d1f479b6264fa09991a2685ba372011af22f9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string121 = /52fd942b96c1251abbde6cf9908edae5b2d325791e689a65c6ab028e2de689a3/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string122 = /532a20950a7c2ed819e89c04f70cd0b9d1f42507f29f8850e7c4720d17cbed5f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string123 = /53e18a3e3ac71cf173f06cc3f01a00744fa0b1c3af7ba8de1e62b881299247a1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string124 = /541d58d2674466283a1d43faf0b7a0dba0cc29e67f2112bde3ac3d9384531446/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string125 = /5521ddf91976c978d2cf175fc1637c1d201ae868e3df70e7d7a5f82db9bc2829/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string126 = /553a143020a31eef62e4c616b44a15e63549897111af6d5c472ec46ec02bc240/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string127 = /556604aedbff01f33a7df0040641cf6bad183eab1c84a5ecdd90521762b04c54/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string128 = /55aba2fe1944249b237e454bba9302328d526b11ace6ac9abe31532ef3598501/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string129 = /56413e30a0f7b6386b0caa4048c7fc5eafa1df9d8966f84bde08fc0cde16c2de/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string130 = /564fdc3bdd17f8574a94502ea54a02cf39b0b93ef44c09af38446d4478304a12/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string131 = /5693e15e2266306f4a9f8a0ab4abc687593f5295beb09b7804af997efc05c6a5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string132 = /5767888351c96bd64880150630f6271d79c3a88053967a7b01da85b74b1ed7fe/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string133 = /57ea373248f438fc9138d17c018defcbf8668884f234d451da112fd544667d83/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string134 = /58975a07474741bbe65b5cb0acccc8a20896027e1365d5543a2a9217d55ef879/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string135 = /5943c0cb2c044eb24b14969bd9b07c3c0edab83446fb9bc8188cc896f218a065/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string136 = /598f347942f32d2f22b6d95d78f3b92529f7cc6e7b6ca2fb083e118810f8c6ab/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string137 = /5b020af1ed925fa5f405807ccf366f99a771702ac120da1a7ef11d1b0f6d1981/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string138 = /5b0880987e5159342e78b77b382eec3cd12365cf2150ed486ebf17dca71902b3/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string139 = /5bb980340a76e2f2ee12af9345d5662a84cc013346746c6fb6c8271e201ac9d2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string140 = /5d03288b02fce093ba94dd2933cfbaccdaa378bb8c38e64d14956dfb7601928c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string141 = /5d80699a96aa3f8d7530f5dc55c4719b2470171539fcd957a6940811b18d5e1c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string142 = /5d974cc94472018668a57f0ba0e66282466ced01f69445542bba4a4da479e298/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string143 = /5dfe5309135b7c12dcadee7bc3631bd4fffb37979dd7495758a68939e89db575/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string144 = /602e1ec82a4e6904a567a7e4c979b83a38fd5d734dd3d614d947365d40d5d579/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string145 = /616e73276b689f751dab7542c8b884ec883c54559b4877816bc815b619bc1ce9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string146 = /6315ca3522a2846e520579222af0ef4ae8db9d9f94046e9ea507bb7a22d81b6f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string147 = /6339e33836fd201a43b6cf193789135c21b9cb8d3de526b6b91540991f42c51d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string148 = /633d4692872611822975590e70d341e38eb6bb4f97c3a3e61f501193c1c5a101/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string149 = /63583c53c98e8ce473102325800fa6c9fe7ea1bc5be5d472052a279ce0015ad0/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string150 = /63adf3a9c56126fa024fea0bb7f4c175bbfe48c4fe06b016985ffea27142c5d8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string151 = /63ee1eb3f80d8eb690404beaee64db746c1b94158fef0933f441692eeff43fa8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string152 = /64a0a19cce004d6f35a0995ac42f960e7a4b78f56b03a2937e8e9459312a31b2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string153 = /65d40e2b26a32fa02e585c939c5c59e97d0d11629197b0826f837b402f8e9b50/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string154 = /67e582bc87c9c0d604ac539ba02c954f56f0ba59fc33c6aa52c145674561d811/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string155 = /67f8ab8f84f3f38e993bee454179fe95008c62fa6c44b385306c3617718e4204/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string156 = /68e8b94f99f449c2b03f908cc77399831c145d289e18f18fe21cffc4010021ca/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string157 = /69d26456753b5aad2c91b4a6a5449a66f24554d51e777fe79d5db45c58345887/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string158 = /6a39044b1dc482bfb03eca45d9c4b9874fb538a13f52c90a2ed64f91152d466c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string159 = /6a4774242342d05732cabe098a56b1948d90f97fe72f464e347315b6d0e0becc/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string160 = /6a88063e6945b8812f30c17209dc3eb3f3449d4ac0e5f80f0dbbee8d74889c0f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string161 = /6ab35eafc987bec331424733bd59804b320ce0801bcb96aa6fa854a23233d9a2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string162 = /6ae454a1437a68e791160c093bb80d0acc962d8116ae672421e40fc418cdc4fd/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string163 = /6b30df4eb8183003bea2c86c7c52b5e555a56b3f127715a0ebf0afb22b719972/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string164 = /6c66a39e447a7bfd2e7c2fab4a3f05ba7e97d1a1cd88a384ee6c703f652d81ed/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string165 = /6c875bb7e4b35df7144d52eac30c8e2e1fd2ca0e60edbfbfb60043b75d6f0cc5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string166 = /6cb25fb99c1fc66e8b2f04aa80840355e137f5248f62b53422d3ab055c9e7c00/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string167 = /6cbd379b042c7b27ba4d446c5cbf755b9991d357895f99076ac0a993f80c4fb9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string168 = /6ce287235d5d056b96a9a99c3a0ce5a209f43745c1101d8e18bd95ea6e7dee65/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string169 = /6e11cfde1949b9171ce570ae5e3b8a7840f12f8f24781c2b3ac37d88627d82ba/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string170 = /6ed116ea8ed867e975f1563cd931fb3b28931a66d8e5548c3ee8fdb58faf538e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string171 = /6f58574cdb2d60ccd01fb4e72d1a03de02dd4992858f8ebbb74cb40d543ebbe9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string172 = /6f80905117b3415c1a1a964d77a273402c3c80952715254b09e26d3a70fbff7c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string173 = /6f82b7afdaff95ea893b1dda21edf5b091a186a2ec9f2883954f8a9eba5c75fa/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string174 = /7002cdf8ac44f3624ad432ec91b999012b0c3c8f91ffe230b9d0b8bb534e9723/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string175 = /70511b1931a5d27f0f44bf8a3dbfd731b318b1914e743ff9aff00d8d86a8200b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string176 = /7056cfa64f838c96283c9df4f6318b952b0eca88de761fa37562c56b28f21220/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string177 = /705c75cc65b5a149efce2441e69749ad714da4a6d142a8b948b5ecb9e98ed69c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string178 = /7281b10dd085f5ffe91de5fc1139d1bbf04cc080d542e0a57ae9358eca94f705/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string179 = /72d6fef7a943dfe5632fca4c573e041367b14f2211770fd7ac4c73955c865dce/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string180 = /7307d71219a8bf7b0d62ab2975d4ea397dbcf3f277f3e4cdbcea58fe08f55b36/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string181 = /733b028d3299bcdcb8998b97939f0b57da0c66b62f52dbb48c29ca29b5c52b9a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string182 = /751381cb88f4fc0c53f9cdfca7a4d217121eef8defb5555728101e5e7d42161b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string183 = /75216b97bd835abddaadc142f709b03fa70a513d3c37fa9a013ecb9536a92bb4/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string184 = /75389828365fcfac51834295aa9acffcd676181fbcee6301f1963662b6666407/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string185 = /754f258d13d79689b39e46650ccdfbd876e8b2edb945ad5d749789b5161f0ff5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string186 = /7617851366772c98b3aae629f0ec8e63a7863c279e2d8f40875f3c6a50aa0a9f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string187 = /765a18c16ac5311b5b5b9c0c3e553e88a7d015322b32eef20989dcefd66c565e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string188 = /7665f456d4b6dd682580898bf304b351b196a1913f3687134478eea4e42a2600/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string189 = /76a92f0af17e901f6a96d4a1747fa67bab25d2d9a154039742351930865d1bf9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string190 = /76d9173d54c6b86022b37c6f8cb1b1585f5613b158c2e6e2baf6ccf45937f234/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string191 = /770553a2a159b19371ea923733997ed2ff71a9e01a04342d1a7fb61c30eed968/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string192 = /77922162f5272f854af4755ff5bb43331b2e63f7cedc7efc30dd6bb3549b2cd0/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string193 = /77f75c3af77b7963703d621b6bb262309b8100b08e42d5a41ab99b1aa86d2f88/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string194 = /7821bc03a533800e3e0ce647b2901934e6bf214209c95262e672f1f04ed1a08c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string195 = /7867f83c0599dc48a1a709b0a0bbfe4f4af72f8cdf14bbae58fdf5e461f1ca26/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string196 = /78a76b1d3ceef1a911bcf34067fee7546c3ee72d7f68a4a8a2da68812eaab49e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string197 = /7952f508ed86aab60e0ffa5ac2a0af0e76eebc9d840cd3cad351adcb64adccc3/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string198 = /79565b23f130ffaeb3f02f6775acf74a3368368b010ed56d3b49bac6485b3b74/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string199 = /79867cf5f18de28036b96ac1beaa8aaa43c3fb44676d25173c592c16312ca9c7/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string200 = /79e31f821d147c4db713a2a7381810a2588105f592e22d21872b38be0b0aa758/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string201 = /7aeed302866656fbf84a03a45315c5b085ba45315b178732059e219a87f81644/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string202 = /7c3c699693507772f6c20be4e9caa31b74b7bf87bf6b7db9f3293c51de05b801/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string203 = /7d65bb1ac457f40d6b4fa1b6ccbcba7e153940568b50d7119fc3135cdb6ecbab/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string204 = /7df4d9b5a4c5a9f74497a4493fa1c4fe28d3e8f4436fcea903bd2b63e006951b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string205 = /7eaaaa6fe51a14b8e5ad3f4163024c3230ef8ca9f1c0b5b039ba16b6a11fbf7d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string206 = /80897c682d005f5382cd3da5121a2e394f293213848c7e0bc0747381481b142a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string207 = /81b03c89401930471bcb79a16998e446fa63b1412b2bd32cc25e175b0bbd7ee9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string208 = /81ccd233e6830ef2e6f9e2be11588fa65df5bde1fad76f46d161814f6f18f785/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string209 = /81d83bf089c11822c0215544c70718ef1577c0d6b27d6f93535ea0b3fdd07f57/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string210 = /82120dbb875df3481d154d0cc4d420c3835a57534f8ab2e9795f239b58d5987a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string211 = /8227f4b2d421a5bfb565d45f8abccd5d0cbda6e2fe6a4caab5bb6078158245d2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string212 = /82c7500571fe91c65c7d8a1eb771581a0f2ab73e35a91241fc14062fccdcd711/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string213 = /82f53311c29da5884441a1dc621dc7087dc1b0e343ec160ed26c0fff4eadfe1f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string214 = /83027372a543334309f8f262ede34349db3a09ff2ac4ab143c465a27c274d90a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string215 = /836385a2fd220d28afd32c8953ef06ae1e13ca36fadfdef901bcd8796e482f98/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string216 = /83cc5974bd89d073642b0c07af35cd89db85a1f3b3cf1e49047592076e94c913/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string217 = /84f9a0b27d27d5eeb6d0e9a5eaffb858feefa1f5d2f0e8af9a654165e37dcf21/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string218 = /855322cbaedbf7d7ea08a730405d5969a4f754a75571791b357d8ddce030e89f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string219 = /8708e2f8c867cf8fda8303837364b2b0184cfa6984febd6c218dc92ee318ea55/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string220 = /87243dc6506269a0a678c529ba9717e9c810cc83f563f92833f177e5c516703d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string221 = /889b051531cf8ec665b0f1730e4ed69e70949341166ff531d703f9e5b8f448ce/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string222 = /89f57029ae1ecd8d584040360ea4450d4bbd20e1339fd6c1c2ce6faaf7a1e8a9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string223 = /8bf810cf013331cf9ee984714251d0e7963b431588ab419e0b83824d8754ab67/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string224 = /8c86f67b69545b19ac0260756440ec1f44ca63ce7cfde3a532a0f4ad6ae883e8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string225 = /8cd2f14abea20f3b1d96f3d535670b7463c8efbd01729fa00abdf20ab69f2792/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string226 = /8e56993ac94d62cedebac2d57693f96fe51b40b8b5ca8e9b6cf3e5845f6e9342/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string227 = /8e6eda0e8e14ac796434d506f11f68e1c25b44758c4a1eecc0b48a53c39cb7be/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string228 = /8ef6d74b5bea0620df5683dff79370b6308fe6bbfaa07cbffee08a26950cffbe/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string229 = /8f3975294d590878d7c5cfc015c2fa1a0ac7b4d316f5f2e62c42cc1473d1f1be/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string230 = /8f42a2c94a2d7f651e114afca2b89ac93f0a8774f5d9dbb8d15b5a8300120273/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string231 = /8fcb35dfb7c7decc047cc08442a59f92aad7eef538a1c46e7989240bdb17037a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string232 = /9124efc00f77a6de28cc12e89c35e1eccde6523a5304556613c45c797b7efaeb/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string233 = /91da2d7160926f0af9a398e5ec09328edf59386e14553a052d26f6b44eec642d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string234 = /925c2a5e0070046e8fa0152782f4fa43f042f4364597239c414490a4b25f3811/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string235 = /9280bca757757d39ae4f71993d27f64952fc1a5dcf73c542cb9d1350b8f22049/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string236 = /92cc7e1364616744e3d3c5d0cfede29516c30da1aeeb5ce95329917814b331af/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string237 = /9348d115c278c8cdd93b04c7da312199c6c93c624812b77168fba9f77a3b6ecc/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string238 = /94862eccf19a77022f230e9e6817b4b20f55c1e5e86d3a910595ec7235a2846d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string239 = /96054c7a1c25aacb70e877dbc44a19ba6125e619d78b4c4455945d06a746181f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string240 = /966526b35beca04fb98c6fe4490a79635ca5bbeef56c21fd118c95ac80ff2ddb/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string241 = /979ace218709961112c1d80bfac298c5cf6b2b92a798b0af012aab2dd45ba2c1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string242 = /97b5f34a741ea6fd544439fbd6614de3960e82ae56c8ef02399ea8935816994d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string243 = /98449032055b0658d49bc712656d9ccddb13d46c87d623344fd1829601b3ec7f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string244 = /989c13f0254e514c0ac261973a6d736917bf10af88b3ded86df954305b838640/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string245 = /9a620615e1f187058c3141b16c20e9622a7aa2a095f84783f91d55b0a8ea7e28/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string246 = /9b897f1e3f2a174e48499a060b1017b67e8ea49991b6d3f673fadb96abae6273/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string247 = /9c6da7fb7b5e60318880442374b369ec6be4a6d39c76bc18c9e4603631a5fc6c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string248 = /9d91266126b654f10b15b28b1852307f73d749b64021db3ec62fea1002bfe621/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string249 = /9da01c8f4125470c56a2d67eea6dff6a15d2b9b9ce084ad42171c85d36ebde6c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string250 = /9db8218a9e3f41f406e9a3e0d23148069275d3a0ec0139e081d9d52ea40d3386/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string251 = /9ebd06f50a0d1e1cd7b6d00a2bda96120af6284799a1400894e4898a9a59e13f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string252 = /9f35e54b759b872926a8564d1b39f763a5a25015c70d401ed5f8acbe1fefe632/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string253 = /9f8ba7d3f6abf2e98e5ec5e0257b65907a5f66b2d28ef80df212c347faaf1179/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string254 = /9f9587864f9b2929cf6af970170d36915110feb1e4c772529b8aa52e5b563d3a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string255 = /9f9b6e450c8c20f087105c41a845937e64401d40e5bdc06dfc38c0c2cfe8e7dd/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string256 = /9fe31fab0dab2f646ca5703beb86d5659ddb7bc6f8f20640c0e1c04b10879136/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string257 = /a03d2b77a947deea62b87b2d30528a68729cce0614b0fe3aab9f280b9c2186eb/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string258 = /a08a45f16e52e6e3ec41d195cb1d6bd4ecfd748c47970bd522e9eae8b2575c0e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string259 = /a0e70901c1b7a25d6bcba8c7dac024c7fdd9641f8a687ae39deb7217f4c09411/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string260 = /a24bd6262d411361edc53e8524b6ed92bccc046af52ac1218f51c9f810109796/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string261 = /a2ba6578e740b1a7369d79eb4087f99a3c5ab082def76bb7510e14fff041283b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string262 = /a3af5883965557d84c10d70c96b4f8c559562bf6428cdb10893277918acef863/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string263 = /a3b70c73e64ed076672aa098f10baaa91dea2c33283c4aea33a260f9de287cda/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string264 = /a48043a8756908a15c435bbab7ddcfc26d6462fbba9f7597e581535743c8a3cf/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string265 = /a4b8bd1215b90dccd2c0d3241bbac4bad1430eaceb342f80097f0e3b93c2ab9a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string266 = /a54ed10a2548f64bcf0a001636ab3578d277c3512cef54f0b0682d34266c8e6c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string267 = /a55f10e25a55f8d9d324cea77b455f4cbd711787a4ba874d2fd9255a30f39095/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string268 = /a5da70fc881d99acc6cfc396eac2ed67957e89831a202e8610f3f48e2f181d8b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string269 = /a615cf0f8929fd2950964a454bfb9ccdbd23c4ddda337035c9daa3ecb03859fe/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string270 = /a6ac2ea4562765fec4f8a9648b57983ea620dd93122567d3db8e996ea14194f1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string271 = /a6b199a57d6b2f7bc067e6dfa8433f8236b51e43a171b262289a948d6ea43472/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string272 = /a6fb80cdc98d67bc7276ea726507b34ebb741345ff6b61973580c25bc1fa84dc/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string273 = /a82b9a0c081af7c9628d7e2b3b70fbf0e1aa89c3cfc2778c177aae45cb394d71/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string274 = /a91430b2ee1746fc061185f83393343b6bbb80f7501366da360cf687b7cb2ec6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string275 = /a949f0e018ba13b735bd96ed729672c72233f1c4a993eda2e60c301b42de1d7d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string276 = /aa76179bd24e773ebf82edcbc58ba4f82c7b660883cc504d40f915fdabd35112/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string277 = /aaa488ddde993d708967f1bd5ec942b367cf04abf5bcac865a5361319075c615/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string278 = /aaee8c23fcc20569816c9f29b25df968cddf3836e80f2ff6b509a0caef68ffc5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string279 = /aaff9defdd75eb977d2b48f3dfca82641c91a243f04ca99975034880e2170b28/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string280 = /ab81070a84a4b8b80543cb31f3aa3829e325fbddef1ba9f048a99c1080b8ed71/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string281 = /aca56ff9f53e0eb7aa21022d1878c645badcc301aff0277794450830b14905c8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string282 = /aca84bf57ae794734cda84fb8208abed12a248067e7012c2fde2718dce7b41b3/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string283 = /ad7e24d0f08fbea59de51b1b3e0212dbe394572856b833bffaa215f9abb7bb96/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string284 = /ad86a839998173ce0349e06fcf1afe4c494490d071d10a3486671b03f0846485/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string285 = /ae0d5b4ee3612accbbf88d53c4ae042ffcccca75a6ca0c8b352a3c7d7d2f34a5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string286 = /aeebe34b285a98fe37de5b3128ea9e302b9feef62ca1b5a85fa41208e328433d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string287 = /af61365c5ecb82162a79a74e76ab1711e8f85c4fcdcd9b7fee76e8e590050d53/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string288 = /afd6b1709549377d5dc7d34f2ed69722f563a0c265dad53d5a7a185ac1b7fd72/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string289 = /afefe0380e25f02064d72df3e13645de51d59879b31b5d741e4458fdf9ebaa81/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string290 = /b23cad6402b0c5f9fd57be07243481a351cf32a0629d7cc03551d1621a6c208c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string291 = /b270e67a46481326734fafba78c9ba47d645754b98986d56b053d76cfc649467/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string292 = /b280f4b1b67ec990eb9522eb93f9d04825e0b31ff183d9f4df9b6db89ed832a9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string293 = /b3bd575e9d0dfd646355151333d400d81f9f7250a51937004809ad922d8e049b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string294 = /b3c00fe058ad002b26112c1989f4237d986b6cf5c9e3dfd5029d0c9169330f34/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string295 = /b3c03d75ad1fb5de827f2749a16b03e355d9f63651c29629d979d57074e79c09/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string296 = /b3d8d191ad67acaae2773e5fcd477a265629902f364f5b6b51b308c6ee228a79/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string297 = /b453e2257ae08240b0fba5a6828aa119af8bc027e5fcb5600542d5d3c2706ab4/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string298 = /b4811fd8d4da079398d21dbb0e8b301ef75ff6a31e1ea2d9357c521a019d0c0e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string299 = /b4bcf5f83ad72c100e50a9590dd23bb35ac70a6331686e6c6a50339d608e671a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string300 = /b4f113933c223da5cfbb72f5a4ff0c3b1bf54c0d25e56045dea7621ea1021d38/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string301 = /b4fe69c527b9455500142ea58f2a16af2eb9fdfcc7d63079ccf9cb463025ee97/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string302 = /b50fdc8caa85dadb573564b7ab742bb7dfdf0062b3f639adf677d698ec0c81c2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string303 = /b52197072372512053ebf764300a93a6e7957a257cd6524a1458bbafc4dcb33f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string304 = /b5353522d8bc03a2af708da3c93bb2f21d0b3bc9a158018b4613c3b66725aad4/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string305 = /b55327db315e4dee5dd8c93b20b5d503613d64a2e1b181263f4715c6c312bb7c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string306 = /b73fbf8da2f5fdb2cc06ee3d3995e1b63f03b34ce734bf1bdde49bb15af3f696/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string307 = /b75fb086b5f0f38428c19a54675729901ca63bb056f48e99bf4a848263ccd901/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string308 = /b8a902ac3876c007c2e9ccef7a508430b5a8cc6dbcbf9794861bb8f62c82f064/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string309 = /b8f82558b584911473782894f452d3807367b378e8fd1e5be7956e53c4baf1dc/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string310 = /ba18587fbe9f6bdf1f7cfe3c3e9c102775fc4aada581dfc058dc9e781e75de01/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string311 = /bacd13f058e7510d63f1958a1aa67acea3e5f74059577dbdafe0420f74e69c05/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string312 = /bb0234c8e7cb409a5032ac771706072ba1dfe49a72f934b11a0b0b6ef3437468/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string313 = /bb2cfc48d0c06e32022593e6f3184d4e5b7b7c5f902938aad8f5d6181ac0d40d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string314 = /bb5173e021c5e905809d7956cb5871edf062418d9227b553599480455d9e2524/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string315 = /bbe4f27231eb9b0b5f7f223d84fa323de69b1575f4b391d7de0614325a97c24d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string316 = /bc887f2d746cb1605a42773ba27c00865d2ba1e7a3ee091b91cdb7f581b7f7fb/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string317 = /bcdb12d84f9915e48e5c453e8aac9be685750e11851dea0c96967ccc61f19e57/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string318 = /bce36da8d85f5bd0c1f0c6f922cc23f943a98cc6e5feea7d307121b68971f969/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string319 = /bd402defef6c6e9f3872365b7baca15d0d1ecc928eacdcae9026f93b600c58d1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string320 = /bdb2c6169980065f48ba91647b1f19e82453dc839278badba882e50f1bbd823e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string321 = /bdb5649ff5beaed52016af493e446ae628e064dc663f181141bd1b7e7b360a42/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string322 = /bdde4cad60ba279c32c416cee47783f8fbbc7723cc2ab5dbed096ced5d88c6a6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string323 = /be224373f60705c94e87de8024ae646302fc29643e3f1f15ab0e84f1c375353b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string324 = /be26213aa79b0c414ff4566b23bccef80d7b5a8bb8a022b5b64c2ca3a5659ac1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string325 = /beec549317fffcc123e613d5f931f5c4441e7b77ef09a21582a795d3fee816f5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string326 = /c03c789b4a4f2b16feb984d81f4c6a0ccbb74449f4402ec1df19be509d9314cc/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string327 = /c070a38e1e877bdcfea1b389ed0089dc7b133acad33b2458cc1575ade877322f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string328 = /c0dad6868eb7c797c29eda978260136be4e5c097c1a3187e3d35db66bf140946/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string329 = /c180bfdab317b545e167896e4a622cb9f9bfb0f1e8e44ed58e1f958dde94d1ed/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string330 = /c26ec6ee7d0d59e1db1f8934b903bd667901875ce09379e873178f6142bf4cea/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string331 = /c2d02d102fc5d471aae2cf7448c9a5d5f9b9ae7a0138b1c78ae122a47fd25142/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string332 = /c338e7dea1af4808f1658121b1e22e50d3a1338f338a90aa4ac33b1a8a4271a1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string333 = /c37051ec2ad197c69fb617c478609636ab2ed040024957e12c5e0a6de3eddd03/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string334 = /c5ced80616a473bd03777cf21da8a2126d107dea8c415a52bb5f7ea736d65306/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string335 = /c63d200f9bd6313d10c66c9418104290ea09c893d7bb8c830a5da53926912464/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string336 = /c729c62e99676b82fc639b5dc2877c044194933ae32406d532d8e5a8e86590af/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string337 = /c76b2b12624877a95f172da43a31f7946c13c6bda3b792610411f7c709c8069b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string338 = /c7fe63930a8f7983a9c2989ce91628bf852349d77842bfbd5d77543c47a7dd74/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string339 = /c8136e16bcb8f48bfe975afa4a490f47c6ea96063380cbed21a95ac1c1f73dcc/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string340 = /c89b7fe9c1dc0d1ad5aafcac7cdadc593bfa70c267e365a2b02df479c1ec9a0c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string341 = /c9d40a5ec773680f943308b52b64ba1a4d37863570da23b5f4f7801012eff3f9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string342 = /c9e90cee55ca810c9fd750d6816e523aa86dce12bbfbf3d448440bbdacdcb31c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string343 = /c9fb545f82ab77dbd39435af7b84aa618dc47e8463722d9532f16172545a659f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string344 = /ca13fecd8bd94170c12cb9de6c12b644bdea34c9d8c14de6a4065b30c6b1c20a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string345 = /ca2c406c54af4a1dc16d98a018d8d1e565dae5e95e250ccce1904dedf351e865/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string346 = /ca2d675d9ac02a80e7b2893de9a509f905075e56e0820924ae57da696a1ebd68/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string347 = /cae47439ed3f0e93f2a67569bc8beaa43935db88e1e716abe014812c2c2b3725/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string348 = /cb0bacc6cda2b791aca69d7ac01f3e43ab2d747e037b1ca0d5779b58b5a72798/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string349 = /cb3d6fffb558efda2aca145d63aac6e1501dee7be14f8d2e9a3d3f3c369fc6e2/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string350 = /cb4af671a007c51441f62673948dda869f7e746f791e2ff776de9a17ff900e65/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string351 = /cb7615b1cee96548eeaaa7a8319f6a64310052e7f6bdc54529dd7f4b8c0c2845/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string352 = /cbc3576e68c1b71336ccdbd3872474fd7dff23932ae2dd4f310bf22551187281/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string353 = /cc07636703d3e6ee9a011ffa8730cabbe9d49453fac9eb8a428fee4c36621453/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string354 = /cc30035b9a609304bf7b3541906aa49379b71df79c92b58ff5f957c4fd40a20e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string355 = /cc541572d615cace2e8ea366aa1a91568559bd5f248405faba88a0d92a6e3211/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string356 = /cc715f31541c012d18607fa572cb5d802bfd4623a91d7ee0159e36ec3f2e5759/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string357 = /cc9bd06b6d3513a61aa3f3f0f4e05072eb0ba40b46a1584b128fb46ccac87643/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string358 = /ccc1e522d2aed22b0cbc91a47fd0513689add203aa8e6d8a0857a430b00ab4a6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string359 = /ce14d0dea73e7da1599d098035aca77ad80388cf3f9c8f8a39aefc90cfae59a7/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string360 = /cf112c0d0d54cb34784dca2a61ee9e119e5e7804e38f55aa435fd885ba8f6d5b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string361 = /cf27aacb093a56d56b3e6a0f5d6d1992fb1b69465e14fcb1ef13c9a57989dbad/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string362 = /cf3d0e1a42c7631616c6efb3134aa8fb0822ce9e27ed2f2427d14634f12e1209/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string363 = /cf40d8f944e06150ba37c216c6c5899bb4618374eee80347e11e3f3e21b9968b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string364 = /cfa67ee856362f2ee50affde932411c76eaa74329a59141b6c5c0ccbf65031c8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string365 = /d085bf919dd44d0f756996237cc655eb5569ee00dc91ae02a7041ea369acc4c6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string366 = /d0eb83464046e448c2cc8681cbcc6de557c539fd307ce46a5734dfbfe6b7be69/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string367 = /d0ff7aed5b06c8bc511a222be3c1f6fe145b253b2fa4ffe62d72e5479f5a918e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string368 = /d1d579c00e86fb281fe7dab503014ecdf9777d85bd9ce50b079a221f344c0ab9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string369 = /d36d52f798b5f83599fcfefc4051370bd353cffb8ec822f81a2cb7401ac9a667/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string370 = /d38d527d1e62c67ee117a812e6de41f422d7707b40b291ca87e73ac44e2de6fe/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string371 = /d3a8f179535cb7e3e16929e3e65811416d7775673d9abbeeca8d814f5bfa927a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string372 = /d4ba62aaa1120d8a12463700e71ac099083c7c4c4a38ac77af15c2d5c3737673/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string373 = /d4bb1f16adc4ec3db363c0fd9c54268843af2654287173e23c9daf6ebf5f671d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string374 = /d5930d27f2cb09241e6d7761b334762e738f8d6937a0bf23df1a3f453d2bb4bd/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string375 = /d6b5056c0a990f73c3f22aee2a6065812d1f78fc87e0362877716ddffd71d831/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string376 = /d6ffeb0cc599c198e2d7e053777e06273dc45fb08ede6fc8a529eed81792f9d1/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string377 = /d8580cfe02f5f7682e56daf8776a4394c199fa8018c51b8eed3f2c3a60c5edec/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string378 = /d8e73a53beb2ef23df43e85a336b235db7dfb075c03aa13534a9881d25c887d5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string379 = /d901c1e7b3825ddc88e962d4cf7846e86041b7374c853e8592934857992e1e8b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string380 = /d9845e849fc9239f6f2342103defd46e0fd67d11d54b152cd7d9645e892eca15/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string381 = /d99bc545d75d6d7bcb95e5cebb2f469da2c0778b6ee294e190f02100b8a4f0a7/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string382 = /d9b60cb1a10bd59a3cfa900e13ffd3592b214c9c22a9cf3812581ac845c3c594/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string383 = /dba60efb94e99af6e6e52c487919380d59b6071b310f30ee0f29f50365c84f6d/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string384 = /dd04c6f2ba77715ff269edd6cc092599ddf0e8c5a9f6c47282e9b24d59ec7478/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string385 = /dd98cb29a275ed711f9a4299c45c0e8cc8d0a746bff0c95dee0dcb05a28496af/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string386 = /ddaecd7689624555334daa031c1a7e30c628cc6fbc5327c6c4efdf492444aeae/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string387 = /ddcde0386174b43753d3f5f8e2e301ccfd8ef5a4dd60bb71c1005b6440072696/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string388 = /debf430fa413aa09fcb067ba67e7a9813dc06b5f16ab32fab9686bee1f5639da/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string389 = /dfb60195257e88b1874fe4b859819a377898a3e3fa4fdaefb13010947c2b415a/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string390 = /dff115f0040f56de9d8a11cbdd37e10d55ab03005f13dba0c3b35f66f17cb517/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string391 = /e26ad15ce8889faf79eecbb5b8395b28df02ea622996199e7e4384635b55b14f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string392 = /e2e514386e255c21cdc78a920822cdf2fd8c9b858950d5d0e842edb2a96f3935/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string393 = /e3a16962b218dbe72cc43aea6c66bcf8234775ee159ec54f96758c6f4e019449/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string394 = /e47e58d3e21fb5608f890f81474a0354f42d97018d930d93b07fd83ac5c0e5a6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string395 = /e4b3bf84caac8fcf5055b237a3054181c1f6c6d726317e028dcacdaeea0c9e60/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string396 = /e599639a7aaf6a9ef2c7ca81bb0c61a3ec12796bb9f35e0959390c24d02ee64b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string397 = /e68d7eeec87b2ff9e85cb89198c49f36cace41a13262e8a3c2ce3c4852e192c6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string398 = /e7623b80e9b89fcbd900c11d16445e052c38c52cfd7bf5954a9c373679e07d5e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string399 = /e7935d85498c24998f18b6c34083d44504c2f35481d8ced208e7167ca74f46c8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string400 = /e97965976cb84019118fee8e28bf175735ed5f65de3c4227bd03ffadb2646d50/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string401 = /ea256adf2c7038dbbfa75b30c41364c29b9b8680bfccea9ccd33d33c16e63066/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string402 = /ea66527a0ec811d05d7976438d50982fc3c2fd4ad86a6a089b154f7d49de0c0e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string403 = /eae0e50f0914e264a60f84dc2fef44c610d00125a38d70fa6f470fa45b12d1e9/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string404 = /eb86b2983951110f0f06547f3a965f6f0ae9d07b452aa14d23265c73334e1df5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string405 = /eb9df7d669dcabf93689b82371cc913efa490d3912da2101c5f4660f9edbcf7f/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string406 = /eba551ef10f31815b3fcf90ed71df40aa0ed7e4aae4aca05eaef47efd4609e4c/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string407 = /ec0c4d2a63a8eacbd2bc8e93f00b4a0402b3f98a72c9e4218e0d6d7a8e438da6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string408 = /ec465f60755310dd0a79b20e355caf67c0c5f049e1ae8e9b9d1503fe198ef7bb/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string409 = /ed026677076b2698d11c46ffe8389c79069301b985c0c7ed50bcb84c09d28861/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string410 = /ee18de5f0cb000c4b6aaedcfc8fb2f402d45d4f70d5cb87db2d7232b3cd3c204/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string411 = /ee2f6d712d46999e0a71694fbb8eb206c4d6555e187ab4f70257c83446091355/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string412 = /ef9e7ebeb7525e99f2499e07aa6313e65f23047b40f6b5ddad6f5ca5dac9a4a5/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string413 = /efbf6ef9b05be315a4538f28b30a17bc2de051598ecb5cfd45903b1c2fdbcb73/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string414 = /ehang\-io\/nps/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string415 = /\-\-env\sGOPROXY\=https\:\/\/goproxy\.cn/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string416 = /f086a7ee9ea8f85d34a9dada68c8a885ca4222b97ab568e2b5397e09eece98bc/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string417 = /f0a08cae1d8aaea09f48e99965a1ea070de40ddc75830112cfa46f5c37c26306/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string418 = /f1820351dc1390a481acee014d8c630903a5d83f3338f81fe31e86476432513e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string419 = /f25631f72f20a2ce8a443207938a6cffb63d0b48bab281a80dc64a0d315680bf/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string420 = /f28f1fbb388f56f6fda84498734d2de8487c851b6fac9866bbf27dc3852d3e41/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string421 = /f3f65e89ca224b5217cf6869fb4cdb3744f7ac998ccc8aa234706aa88042770b/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string422 = /f44b640e28904ebbaa8ec1b8f44f51b06c36433f8a1f448cc3364f8f2f0710eb/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string423 = /f55346d51dc5695d97ddc5a060ca17f20f1cde41478b2c5e45a98c9549b4a383/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string424 = /f5d12a78dbb405e8dc7b1238ca6825e4f68200cb8aefe56b398957d0ba1d0bcc/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string425 = /f63c29ce8df84e2f6aecfcdd4338ade69d0bca92dd92e45b7373030cfe7539c0/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string426 = /f6ee090c3a4390f45e236b0a169b9b15a6a9094881a9f1336937a9d13d9fc5d6/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string427 = /f757dcfc3ab68b9af0445c5672dd92d8bc246b9135f2896aecbc6f3849f31ad8/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string428 = /f99b4944426d96892d0f6d8e20e7266a407cab5afa1eef1dd9eee791e0a0941e/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string429 = /fa3708cf1fdbefc4aea12781f5f7250388d95e83ba5ae9df08940fd31c1883ff/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string430 = /fbbb6062b35a604ec6a6cf0fd8f8cf298fc6a0551108bfdf4a65c8a03aa92fce/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string431 = /fe0a341f1d837cff5ed9b847e0c61d4c9d5f183c00eff93eeb8c1f0ac3730452/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string432 = /fec3641b2b3bb528832f7d428a701f1621aeabec7a257c8863dad064672b4bb0/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string433 = /ff0724e19316b2eff48ac37d695a0f6dcb09fa297153711c24baf16095e21f23/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string434 = /ffa8bb5d802f08a81815496d7991d3c3be3fd3fe15160bc85dca4cfc1bed7a03/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string435 = /ffdfgdfg\/nps\:latest/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string436 = /go\sbuild\scmd\/npc\/npc\.go/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string437 = /go\sbuild\scmd\/nps\/nps\.go/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string438 = /nohup\s\.\/nps\s\&/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string439 = /sudo\snps\sstart/ nocase ascii wide
        // Description: chinese intranet penetration proxy server
        // Reference: https://github.com/yisier/nps
        $string440 = /yisier\/nps/ nocase ascii wide
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
