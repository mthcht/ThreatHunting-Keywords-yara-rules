rule pgrok
{
    meta:
        description = "Detection patterns for the tool 'pgrok' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pgrok"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string1 = /\sinstall\spgrok/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/jerson/pgrok
        $string2 = /\spgrok\.exe/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/jerson/pgrok
        $string3 = /\spgrokd\.exe/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string4 = /\/app\/pgrokd\// nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/jerson/pgrok
        $string5 = /\/pgrok\.exe/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string6 = /\/pgrok\.git/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string7 = /\/pgrok\.yml/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/jerson/pgrok
        $string8 = /\/pgrokd\.exe/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string9 = /\/pgrokd\.yml/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string10 = /\/pgrokd_.{0,1000}\.zip/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string11 = /\/var\/opt\/pgrokd/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/jerson/pgrok
        $string12 = /\\pgrok\.exe/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string13 = /\\pgrok\.yml/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/jerson/pgrok
        $string14 = /\\pgrokd\.exe/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string15 = /\\pgrokd\.yml/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string16 = /\\pgrokd_.{0,1000}\.zip/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string17 = /\>Poor\sman\'s\sngrok\</ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string18 = /00440c4525e995e54ce65e9d0c85f7482136463c9109c61650687226aca149bc/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string19 = /068793abf6b6c18bfcc9f22207b12de7f25d922960cd5b48e3547851216bc456/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string20 = /073f9b935fa7e67e49cdd53823955c3ec8291fefcc39516f88ac57e2dd9131a1/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string21 = /0c20cf6d65d5dfc9f36005813dc82517043fd635cbb571aa1c1039d3cd5161ec/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string22 = /0fc8c8a3c45bf30f1f09ae9c74e8986c367958d81ba2001c23ee536ca0227fbe/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string23 = /1079079045b66cde89827c0129aff180ad2d67fda71415164a2a3e98f37c40e7/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string24 = /116fae615a600632bd007ea8608b2c814c55a02324f9b8cdd75e63e2b71d53ba/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string25 = /11f6bee5589f447de6fa74890630deb8fc33cae47fdf31907b705a05a27e39b5/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string26 = /17db2b8cf5cb903ef0b04dc10dfa5f24fd9ce7ec75674219f322b15d706935eb/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string27 = /1fe3604bdf69ff5a881a77258a10583a3fea5958aaab958ee4c22080635f64ba/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string28 = /22415883e18cde6e909ddcf683ded67fa419a726557f7124636f980e64b04576/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string29 = /2b92a08a76d9b0e13e41660fdc2491eaeda7b8400f9d29542f27ad2edd004d9f/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string30 = /2bf454abbd1446061cac6ee9f57b12c572c07a3093e45e29b0cdc088ab18238e/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string31 = /2eb58b8d72bebd6f4ca4d55ac855dae5dd7f29b825ad14aba8e4a96e19c5ae54/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string32 = /31dc3fe53dd1ad80d2c5e6ffa9221b62385b1cd2f16ecc240cd59e5f485155cd/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string33 = /349d0d0ecabf954caa8a1a78ab35b16bbc625424e827e008db1c76fd4bd29dc5/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string34 = /35d6b2ef9a31b54ebee2a29bf22bb623bb5c9a74110472268581d6ea8122132c/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string35 = /3892f45ccf44d24fbe3b48933a876414e79e8e9a35f3924ef2dd1c63053f4656/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string36 = /3da0eb5c83daa77c9e52759d3b668774b0bccbe16b87c74301ec08979ffb15d4/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string37 = /3f06328ca39cad23ca718129de65b24c3630dbc51fb473b42405c18a23e21992/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string38 = /4071819358aab734ff8346fa8540427d3735d964d636af6a803f84433e9ca03a/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string39 = /43c68bdc9adf3cea7c3643492732aac7e8731d0abd50fdeab1f9b078801d41a8/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string40 = /46d4423a5cf1811ceb701cd756aa94bcc6d53a3c4ca49d961a4fd2b2a75ab300/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string41 = /47fd3fa87768d26e5e71cd73d507d5faf8ec898ead1ec46487e54c8e0ed63838/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string42 = /48a3acd3b29c436bb696a1486128fa509bd08323eadafb8c7dad54882b45b8f4/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string43 = /4973faa197eedbe906929425c2f85a2f29411fd84e1b0599e4951c07fe5f37be/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string44 = /4aa6c882ba3b5d8a4a62f183f4ea878a9d86dda8e6713c44f0bb16528bc124df/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string45 = /51ae744086e74f4266459e4fec04b65386dce95598a87b961398f85119bbf701/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string46 = /53cb0a4c9d99d9fa9ceb83bc5fe6ac1f8f7100130b1597d9eb71b3a9fdb01fcd/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string47 = /5579149600842ad916cf87ca07c8b8fd81b4a5737d28ba2c66b1e2c72a8cf036/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string48 = /57ec0021464f26379ee9242f6b517b4276fb7e431cd963df8950dcec8c83d6ba/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string49 = /5829a7b027c1fe0c12ba6e6fa4e53e8d21c94de346c0c3919a73da2565561979/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string50 = /5b5327952836163d6a5c2a9ae0d300daebcae8b8066fd2cebf1e3907ccb0b3fd/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string51 = /5e2b755a50d007fc6f5807bae412ea3d35ca448bda47423e0f80a3692e3455a6/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string52 = /5f712eb517e8d795f053d28f443cddea953a0bfa339f78eed68a1c01566d84d3/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string53 = /62dca9e606b8d8c2a1379e791210dece010cd801912d588dbbf3859d00a821da/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string54 = /63ccc3e608d3225793b40e643af2115811668731a2b43cbf5217bfb3d7e01d84/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string55 = /6fec9d5af24c2d845ab1e2146e38196ae9a8ae351442c6fb8a048373befd88d8/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string56 = /763ca50b38753d213fa1c4b3d447ad0b7f595e9251f5471be04c6dae3a034308/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string57 = /78db6e175aac64df82c8c51798da5dcedeb82559fa7cdcc489a718f87c385203/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string58 = /79ae34d44a22c9c5e7f1eb1d60fc19e8ab43120cdf0852d8e17ea62ee39669ac/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string59 = /7a75ffa6b95556dfc5841eed63d45ad41eb495c0da386aa4f61ddf209a529075/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string60 = /7be3968468ba873800b67376c017a529418f1aa250f65577776b9630641f2468/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string61 = /7ffdce15d8adc97dcaaa845d3e7f493b9750103f4e0e6a3e5281109d93272374/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string62 = /81e16f20ad480d901964c4b9bfc2f0321a4693cb123f4d3148277bd9f7bc3f5d/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string63 = /8513ddc466aa21460a7790754d7f9441725820996f68ae44731bd63fb8abd957/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string64 = /8572bd593860c780a609128b9764e2f98e13ebf7130018e288f067bc75c71ef3/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string65 = /869076f7f55c9cecc46bcef4b7c44a7538f2af695ff8ce728c71a0d52c48443b/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string66 = /89c0d3180d1baa0b0ca6fb7dd3af81a80400ea4c5674101a5800c074bd3aec98/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string67 = /8c3d91b1b0f23fa6998de41c1f4c12eab9f14e39fc224d3055477fbdf0c8a7aa/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string68 = /8d2162fe492d7be3c17eb6578d8fcdedaeffe2294156a3f898f0cdb1fb6c10a8/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string69 = /92ba52da6b5b623559117809305a93ee9ad6da07ea6352efec349e8d2760d307/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string70 = /9827e63054ddec1ffe0f246f9bb0c0de0d30deac2055481b44304d13cc928fe2/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string71 = /99e0f20ad43baaff5a1a38d9bb0e98a2b2269b8fc6ac3c3ff6fb70b802fb6911/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string72 = /9b6ebca62874fff570d19b1d7eeee8eca39f0e9fe1c5496930413527fceaf85a/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string73 = /9c86d0fbe739883dc37c81ff6a9e4fa7f06417c56fa52ad6ceb6ba7bc3e9f420/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string74 = /9dd63128c55bdc6f062713958960f7bdec1983051df3114d9cfc2037089686c3/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string75 = /9f6ee8fe7fea7bb68fed2ca7626a9277af8990ff8ee565c03ca3eecc083717df/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string76 = /a2551565a931107db6e9ed883c7252bcfb51b185f95d598cffc30dc7997c4d61/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string77 = /a2e65bd4579385605e7233852bea4627cf94a2ee83e6233d462740b7e930c284/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string78 = /a483e9f06a8e03c3a09028279f8a03380dfc41c5ee85327763e684c866f9019f/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string79 = /a8a01db928e625521789fb4187b72857049ea2542d1795afbe581ed6d77e6bc1/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string80 = /a8ab4a99f65193c1bba3f8864a0f1d39e8d7c97843b4ac0fbacc98fe1d2ec161/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string81 = /a8effdadf86dd52ed13ab8051982927ea464500c36b4d0c1fff5158da2b4abed/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string82 = /a920c6b7605a82318a7f60f4a2bcab191359f6187983bbb82e56a6fe2cd7418d/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string83 = /application_name\=\'pgrokd\'/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string84 = /b1ce529f2a0ff157590b2607388d425ac9a0d076de7f58bb6ee7c14bdb657bd7/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string85 = /b668e7abef3da11ad164c618aff533f225d96fa046034e64485a48eaf5fdaf58/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string86 = /b7efb92268e1e7897c0844e0a0f6c8648173a3c5c2c51d46fa5677b6c58c1dcd/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string87 = /b8714bdc54a797d35052db4d241bf2c5ca1dbd0f0ab549711ccdd0b54b4d1d55/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string88 = /b886f3afc9b5d11dcf8741b00aff8c1f43f1007554ac58f949c7654df0566fed/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string89 = /b9488c840679a25f1afc5666025727d823751107550249b8b28fdda43cf270d2/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string90 = /ba9ae74a938a83efcaee904b800d7bff0b19e02f632c4956bd0361e6a32f4ef3/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string91 = /bdb7525b0af0c8528ee5811393f46ca0905eea38ec615ba68bf86f9d358e9c11/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string92 = /c54778b8dc4e458130197cf95d6fc594cc1b016b70eea917f8a44c2c37c080c7/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string93 = /c6df3acfa4964ce75534e76ea4635280be68c946b8b5d0566a858337e74d5fd3/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string94 = /cbab130e55af45dd1cc7b1644a799b92f7fa4b04f82b93e021e182399b8aefec/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string95 = /cd23ba3117eb39491f3286532575c3ccce97f0445e18352c87799a7f82274c10/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string96 = /cd5b16213c11faffa7ed44becec55368348013aa980e6a38f85f7f2a0aa2b85e/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string97 = /cec943f322857887bed2af7cf0aacb4052dcdb63eb76180f6a2022e3e4133718/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string98 = /cf2a0ea978a7f5a254a046155a39127ae68701a7b4ec51dd2e509b9f217e960f/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string99 = /d0e4117d84d8a5e8a716a6cf6f06128a365465eb83e803a85ecd9ab2671468b4/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string100 = /d110395a75afff8f1e8c54c7ae5fbd9e085ec21da4c472e4fb11346c17d8652d/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string101 = /d273dcfbaab605187495a344d65d3a39f423144bf005a36bee87c292ab202c69/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string102 = /d6541e6233d5baf5190b494f434dcf30943c33d4bb78266cac230eb905a10f50/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string103 = /d789739fc4f5928ee0cb38a4520f9562562cffb2e3a48ab3cd6ba0c6e8b4cfb5/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string104 = /d8d88c5aecf5f0b27208387cc830fd094e2b0e7230a965728a6862ee9c8278e0/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string105 = /d9473d3695626684a9cae93f417516900fd0f21a03f61e6943f50435c762ac73/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string106 = /da409444f4db4761ccf441e1e9ba8ba39ab8e63bf0dcc8054308aa5e805379d6/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string107 = /db20e3d1a1eb02a323d1d3abcdd7adfdb71c04965988edb4e75fbe28c03858bc/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string108 = /dc8ddf520783dad3b74770b0ad90d0201b090ef858dee7971825b7e45424f799/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string109 = /e3bc166f9e3cd64e1eee1061f26cb80347f2cd4997971c91f3ae9cbe5cf35999/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string110 = /ec0b2820e26edffdfbcb1e3e66a78dd1ba830fe37897a3a55bf4602a3e807cef/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string111 = /f4e95340caf77ecf01f0b73c8d2941ff56fcbd908722a827db9bc8931ead693c/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string112 = /f6c2a3ad0c251e7a5c109c6a60127c8e90506d8b71e78598c6a449c7f5c24659/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string113 = /fb10885853b0c5f6a0cb0bc0e5998c430d99ffcb9a5bda1fd03cefe9f3028f7a/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string114 = /fcc37e68c723df92d2c17ce16d8c703a90a0c2f160eeb84c4559457406bfdf57/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string115 = /ff3ae7ab29ef7a21094e07650e8cd4a4291363c2819e2dfbae34520ec762efd7/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string116 = /http\:\/\/127\.0\.0\.1\:3320\/\-\/healthcheck/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string117 = /jerson\/tap\/pgrok/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string118 = /pgrok\shttp\s/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string119 = /pgrok\sinit\s\-\-/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string120 = /pgrok\stcp\s/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string121 = /pgrok\/pgrok/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string122 = /pgrokd\.exmaple\.yml/ nocase ascii wide
        // Description: Poor man's ngrok - a multi-tenant HTTP/TCP reverse tunnel solution through SSH remote port forwarding
        // Reference: https://github.com/pgrok/pgrok
        $string123 = /Reverse\stunnel\sserver\sstarted/ nocase ascii wide

    condition:
        any of them
}
