rule sliver
{
    meta:
        description = "Detection patterns for the tool 'sliver' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sliver"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string1 = /\sbackdoor\s\-\-profile\swindows\-shellcode\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string2 = /\sbeacon_win_default/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string3 = /\sc2profile\.Name/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string4 = /\s\-\-format\sexe\s\s.{0,1000}\s\-\-jitter\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string5 = /\s\-o\ssliver\-server/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string6 = /\ssliver\ssliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string7 = /\ssliver\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string8 = /\ssliver\-client\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string9 = /\ssliver\-client_windows\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string10 = /\ssliver\-client_windows\-386.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string11 = /\ssliver\-client_windows\-amd64.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string12 = /\ssliver\-client_windows\-arm64.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string13 = /\&sliverpb\.KillReq/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string14 = /\.\/sliver\-client_linux/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string15 = /\.SliverRPC\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string16 = /\/\.sliver\/logs/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string17 = /\/\.sliver\-client\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string18 = /\/\.sliver\-client\/configs/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string19 = /\/c2\/tcp\-stager\./ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string20 = /\/c2_test\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string21 = /\/canary\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string22 = /\/command\/exec\/sideload\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string23 = /\/command\/exec\/spawndll\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string24 = /\/CONCRETE_STEEL\.exe\"/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string25 = /\/download\/v.{0,1000}\/sliver\-client_linux/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string26 = /\/download\/v.{0,1000}\/sliver\-client_macos/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string27 = /\/download\/v.{0,1000}\/sliver\-client_macos/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string28 = /\/etc\/systemd\/system\/sliver\.service/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string29 = /\/evasion\/evasion\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string30 = /\/evasion_linux\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string31 = /\/evasion_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string32 = /\/http\-c2\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string33 = /\/keylogger\.cpp/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string34 = /\/keylogger\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string35 = /\/msf\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string36 = /\/netstat_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string37 = /\/ps_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string38 = /\/server\/c2\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string39 = /\/sliver\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string40 = /\/sliver\.git/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string41 = /\/sliver\.pb\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string42 = /\/sliver\.proto/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string43 = /\/sliver\/evasion\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string44 = /\/sliver\-client\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string45 = /\/sliver\-client_linux/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string46 = /\/sliver\-client_linux\.sig/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string47 = /\/sliver\-client_windows\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string48 = /\/sliver\-client_windows\-386.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string49 = /\/sliver\-client_windows\-amd64.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string50 = /\/sliver\-client_windows\-arm64.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string51 = /\/sliverpb\.Exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string52 = /\/sliver\-server/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string53 = /\/sliver\-server_linux/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string54 = /\/spoof\/spoof_windows\./ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string55 = /\/srdi\-shellcode\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string56 = /\/syscalls\/syscalls_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string57 = /\/usr\/local\/bin\/sliver\-server/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string58 = /\\command\\exec\\sideload\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string59 = /\\command\\exec\\spawndll\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string60 = /\\CONCRETE_STEEL\.exe\"/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string61 = /\\sliver\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string62 = /\\sliver\-client\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string63 = /\\sliver\-client_windows\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string64 = /\\sliver\-client_windows\-386.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string65 = /\\sliver\-client_windows\-amd64.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string66 = /\\sliver\-client_windows\-arm64.{0,1000}\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string67 = /\\sliverpb\.Exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string68 = /00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string69 = /013e2375bb6c35daca9df2a98e5ce1c963608129ce70c800fcdecb7cf63be3f8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string70 = /02151e34b45cec985c68b52bc6dcbd2014116d22e92408e19e471e7fdb37baf6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string71 = /033ac18935c14c208d6caf86bcb38ea0422f1ace50be938e56d00a480b8e5611/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string72 = /03c8bb25a392802593dc4cc97bbd596b5059ece8bebd36790bae7f6b7b2eb2c1/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string73 = /0421df6cf7ecab2db20777414d571ce0daeffb52edf58ff6fb873826c4a1f6ad/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string74 = /0430a3e7a1c50c8b42d5129089ca7f31a28d0b4a9aeda7a96a1d686fde52a9e4/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string75 = /04b76edf1ba46b49f42c67669dbc807e550682709c977665c0c7b37d2bb5e0d2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string76 = /050c8a0def9c19dbc64296f5a4834a902756ed06a740bdc7e0170a8748792bd5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string77 = /05703420a4694ddc3d737d5f7dd589ff1288b05fec2bdc6f5b0f1227509429f9/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string78 = /05bdafc5a389b57dab75449e8932ad17eb9871d2767263e6d0576568319974d8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string79 = /05fe66796ef2ccd1e425281d7b042a531891f5914281e22eabbf283635b6d6e9/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string80 = /06e8f3cc9768b22015a52d96357a11185c43c239e887a1346e58eb8ab08c4471/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string81 = /07a474dfcef198d7d5bf8261de06eed7c9528802e9065faf2a63c7ef6b992986/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string82 = /08bdf0baeae215d62da086a06124b26d50d1f77ab021c17a849084648daa7d35/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string83 = /08bf766742ad601442e6200717c9a5ca004de85c350353dd2793b5c29e1db995/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string84 = /09877a6147033fd5a670e8828058d51d71926e684e53582bff7d5c27b6f9501e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string85 = /0acac34993ed96c9c8ba60fd6914937c626330b2e490885fd0b9837e171a3c44/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string86 = /0b79812a3202ddcd7f58de6c1912beed92b163a0ad930193b02f134059d8c420/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string87 = /0c19f220188feff67261fd9ac6448ee06b84b8e836f1e558592c2b381e671194/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string88 = /0c64315cdf7bd0e51e76f04510c91d931b8b4de73f06ea7931666e62cb34739f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string89 = /0c8e33156886e733d0021652fe0a13b03946fc09adb392458fb2a435fb402d85/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string90 = /0ca10134908aead6310e72aae31b7eca8e653ccfa9a2bad686cea277367e4f83/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string91 = /0dfd57cb8299edf2e4a941d39ba787960de83f00b57c4f885bb141782a3b559b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string92 = /0e643bd5e3eaf43f5eee053904a24dac9bf05150885fcb32a606ef3ee1c7db1f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string93 = /0ed7071221412e55b8fa13a88d21ef523186e621acfb3cf3fe0dd292c0a25951/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string94 = /0f62d209e39c648d15f268c68056e5f309d5eb6c7b0eff890f5ccaf9a0e12b96/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string95 = /0fd11529bb961c342b925e156dbda40de75d4d9e823da6136ecb849b74b81e6a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string96 = /10119f906ce65acf48767f222524685945f3c25e8531bad35ad485c6e549ccc1/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string97 = /10fcc7c086208b672ba3c954ce137842102312529937ebd2c3f8060ba70803af/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string98 = /115582571181b99e7b64918a94fe75c24eba2a95da256fff85799d19e6a47b17/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string99 = /11c8f70aac612dfbe48ee5c4be2984d0c32a3a15b4a33f3b352adc7cbdb8c937/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string100 = /11db72b2a60d5be74d95f4a311571f045086efef145562edf02046d97f44f975/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string101 = /13ac39c3d0379d55f1fdab74b78354fd7d8c23ce43e0bd2f86c64ec21f2abe63/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string102 = /142d3b96f2c42d4660afb05c725185377a58cf521667ed4efc360171ffcc2e97/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string103 = /14a0f72e21730cd71eb2c9cf9a22682ac386aac36cca6a270ef01d9c1bd4561e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string104 = /179fff5afdfa8e25f3027ed01a226cb8f0b6ebee516ea2fb8f4e6e226235fe61/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string105 = /1902a53e45aa1a58bca4bd3014df8cf8a2cea4fa312b5fddb44be0ff46900181/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string106 = /1914b76bcb69681a6d7d6b6e0e98793f244073bdbf92e2b7f7d74e11584accbf/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string107 = /1b9b3211b26dcb730d47fa8e7bd97a2c3d5bc4b740a1c6c15fb690c87cd12031/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string108 = /1bd59761e0390b6dee196b67f5cfd3b0dae73cdb5905815cd4ae9d5ae02293f7/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string109 = /1be8d887faf0e80185a811e2c3a734117dcd081136d088295356bb5ddc6395be/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string110 = /1c0f922ca54295ab3f496fded2eada45fa166e32b34bdefc838ba3919c679208/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string111 = /1d523c11769bcf3b85ae63c7d023e531962f46e04dc485c87d69bff6e31635ef/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string112 = /1ecf18a303bf9af2e5fc0f2cda9777bf9a759a88614edc0eb416ac4517fa3746/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string113 = /1eec102c2cf354bbc7ae4c188a88920bed7cabcbf91c8b8cf194c996da73ff6b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string114 = /1f25c454ae331c582fbdb7af8a9839785a795b06a6649d92484b79565f7174ae/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string115 = /1f29193837f8b7b8ba8c473a6949bd1520e54a2880303cd8aceabbb030f13aed/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string116 = /1fd778412efb89cb20d5602a216470af12f9acda80db2680ecd7c206cac208b0/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string117 = /200db4742ae08044ebe53c1ccfd6db3c3cc97597a83c172f7a99aa2f0a60bd99/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string118 = /20185a48e061bc197cedc3f86910f51a97e9ab054c16b7dc2442a462d7222650/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string119 = /21114d71b2fd8ce79dcda7322f26300e4e6aeca8afe659a6054b9bc9eabe1500/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string120 = /219a4c8a8686b08c5f7d98b1386d4445e501b89404fc8dba6abd47bb271d640a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string121 = /21f65143eef8b914b4b044ed3bbd518e05f5d8d08e326cf62e0f63e32de8a73f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string122 = /223068bbe721dda949ae91d8260b2c7ee7b991c409be7d909841874c37c4f073/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string123 = /23b828513db75348a8fcadd5db45d1593a5786a02b7efc1f6afb732db7ee97f2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string124 = /24683c103edd19d58c02b001521660f0eae642200ad42454ae810bd7aefaf46b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string125 = /2562c158d4f10ab67c20710da74463876e093473b56e7e1900a163133c1765b5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string126 = /25ec3ba7a4464210dd357b8454807c4163e761a46ccaa4bdd0b6c77e6b065fa5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string127 = /26311efd632bf07e682b31290fb2815b92e6d7880d21d9b7e87ea1a08c0b4326/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string128 = /284aac919a7582ec6ec1d6c71656c8177c56c1b8734834f66bc17b6d59e74b3c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string129 = /285ee27ec825b9a981a36594658a7943eba63fe0b4237f0110cc57729fbf3b76/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string130 = /295850b32709c33d6cf6719301a9a26b29294f6edda200320e6869ff660915ba/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string131 = /29601a1a4939f36c5d6995124862ce5c3c7e2a64b230fd9f1c04f0f52558b5ad/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string132 = /2a5afbf327864c6b682b15d893504d9e3757e83522ac32e848e69a5e496e1fce/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string133 = /2afcf7aa79d17989aac2b1b3ecca95d2c30659a951d4626e4f0d0fc73e1093f3/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string134 = /2ba719023361de2ac1f7c68c9d4081860aa70eca707662e142f89048d7a89859/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string135 = /2ce6ab2d48d613830f2cd7920ced86ca7b6782dbafe64af84ba476f71d08620e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string136 = /2d320664154077c143296da336e7ac4bcc3f639cee91734ec0e4689b782d17eb/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string137 = /2e54d374300b86e3eaee278745f26cd074023ca2ebfa575f5060032192a1232c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string138 = /2e6a0588c2e9136520122b97ebe2463a37f15ac537121d22873467b275ceb630/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string139 = /2fa02db89575d18c68adbe39e2db1565d9d688adce00b3ba85d6407d3b0cc911/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string140 = /30af65f777eba02b3484f6db7f91b66d465d4497cabf9dd35f7291d5a717a454/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string141 = /33c9dbfdd337a5fb8cc15a62bc9800d9a58799ccf21cb1b9bf3e7b7754c5eca2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string142 = /35151960809a922f735b9492d55792b5cbcef5f3f47060ef484f92f63fe751a9/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string143 = /354f17db4f3eeff8cbfd56f6aabea68deb7045572ba55298bbfb1e355c98a246/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string144 = /35cc4208d80e7a202cef1cf17f6a2d1a629400410eaccecdb70c3c85f79ec431/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string145 = /3697e7b61d4f49ead950dfcc75560c457c836fcbc9f81b15b2041eb2a7a5171c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string146 = /37189960f1e5e6efbc79bf55ef7ee6840cc639ce46905691f89850a950fbdd94/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string147 = /37f49e38ee8cc509bcae0842800b3d0c85072d6e56a8395aede48abeef0b9f28/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string148 = /38a838f0558351bea32e58dd7f5bafe47a66c54c14f2be2cbf1631109377257f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string149 = /3998762030e8de14ef07cd7befce737e4ab9d4fa0682621dedb56e7774a941d5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string150 = /39a32bbb1285b51059b5e7780f3e0b49dff4496e904641219215ea13634aa8fd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string151 = /39a9dada9b6dc223cba7c4cb35efceb7cd9e40345c362c15e4c203d16f65de9f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string152 = /3a596620516109f4f6d5bfe1b2d38f53f04b60f3fff457573dd506ee981aaea3/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string153 = /3a8e6fe87d5cea3b118aa6b900c63cf7c9d0e4fe3c3bced830861f2835caea33/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string154 = /3ac48e132a8186b8302e04c77c22c4ff2984e6b6bd16bf65361cd1b751559703/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string155 = /3b8b9d91a8ddd3d98da746d79aed9a4f21f5b92eb2ff650e7014f924a0f4c0fc/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string156 = /3ba0023aaa84e8e4e063da17b60752631776d3b61646c026cf05c4a1b44c04bf/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string157 = /3c27f3968cf79a0b5e9402eea64b259d0b4e22d08932281a20ff9a67a472911c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string158 = /3d165b4880de5247fc9cc4aca2f0d31fc4cfa52fefc08c18e80c3f5b976b545f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string159 = /3d86ecb9e14e7d1a86e16fa28b61fed96ca5bb9dccbfc1c2f8d1231325755ef1/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string160 = /3e02ce91331011e03e8de89723c52367ff14d75f7f81b94ad3741f9cc56c5736/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string161 = /3fad659152d3559e2630e9e1a0e7d4c6770cfdd2e847ac6d438d852af77e591e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string162 = /3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string163 = /3fe1b764b88336a034bff6db6532c2bc1e389680c54d38b32f2af8322ef1cfcf/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string164 = /40853f24896e8e1ba7170a9775b056195567e6bbaeadb14afbb8312f35112583/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string165 = /410973764272a0d7b03d129471da1fb720dfdc2c9c0b0934b390bb58444b9c50/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string166 = /41710a6994b2ced4ba4d7931ba0312045ef5532d38ea0072c614f23a0983cc5c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string167 = /4181564bd544b3bbb2c49b3b6d800feac2e4438974b650c53ad4882b76d47f92/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string168 = /418835f7a0c331a947db1c4de194394e84c8399d3dcb94cd66182700fc105e49/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string169 = /42c8296e0f553026ef98c9c89a1a6a60613c990621b9f04cf925833eb0572446/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string170 = /437f2e82e5fd2de01257379e1e155f380ad173c35f32a02eeedd1a06a262e8a3/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string171 = /438f9082ae1cd3bc27027e8d1a14adcc96768fe52dea5594e31487d01f0dd250/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string172 = /43ac133ca47ed9916e78d39f8a3bd05bc8ef31f3925ccaa4b24e769f47e2f61f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string173 = /448a280cf39fcebb006e9a66c81b9d59e884f0ed16590ac19d976e44fab7907d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string174 = /45a81bd15482f0fa6be511d3590b8c8d550e80362b5dfe10edc2488043c48cbc/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string175 = /45ebedf8240705e9da3b89591d6e0203764e94a1ba5ebaf999627012e06bebd3/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string176 = /464b89245a6eb6429d6588c6f9b15e5a158e41be1f7ae9ccb6e3b3ba0ca6106d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string177 = /47f65f47bf82b419bd5cc4ef4dc6d538cad4e5006aad4c557d242e31ab492ba4/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string178 = /48359bfb6692ea45f075188b2b244fc8fcec4ef7e80d2c2eecae90d5c9cdd04b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string179 = /4ba56c35ad47ef4c0f778c152717296d353945b500448a332fb533ef5bdaf36e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string180 = /4c33b97878d1d543f60ca27673d99dc8b420628820ce29a6ff9d658f410254a5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string181 = /4d206acc72c76a9e6edcd57584b1fcd3094609212e15ba7f4afb4a9cde3534a1/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string182 = /4debfbce500084f6de01ea2cabbbde5fb6c04c99285dc82047fc53db5a868e5f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string183 = /4e532494ca7946d90f71ace5f8c709fe09de8d20ebf8a0895dda55cf467557e8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string184 = /51005077d771b96d6157772c5c78c59a94284e8bc4396cf7a52309ee262ca129/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string185 = /51357562490b7136ee89fa9aad7715f00c471bdd09c6d36c72eabf3da33db909/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string186 = /51ec632f44196675aac4e358940ac03d5a135a4d7dc150a5ee678203afec9fda/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string187 = /537a987d9bfe60b24a9bef0a9214f64202e91ea5fe14b1c3063317387f595bf7/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string188 = /5400dd85170bb1f4597ffb2d761aab44e311f00b286c423bcf82a2c765bb8bd2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string189 = /543d7ad609377d2797ceba313047cdf1bd601553c3d49e34f58e1ec0ac438ab8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string190 = /54680b2daca9c4051463a646c0ea849190b741081670d933e00ed182b2efcc56/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string191 = /56633694db3e8d8f7022bbc09920592e414c90155e273fbea96b6299bab97275/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string192 = /5696de366805239d730793f8bcb78d54bc2e8c07f06795e089dcfc8f6fed8184/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string193 = /579ba94b0bffde7e8308bae8f7ba129e47f7e36a3ed7e57ce0454d01629c2baa/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string194 = /5c778de24421d1fca1048bde1f9f37e75cd23a127199159d2064da3b26574faf/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string195 = /5ca23515c4b5ea064981ecab60416b9a6b85e6220cd4ea7dff72522993251422/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string196 = /5dd1488efa5a855d71e3b60d9d398f1fcaae367c352e731ced194c0fa261ac95/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string197 = /5e1896cd6c5bc82e6369f5e143bf87a59b37775c7987d36e29ff1846c4863d98/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string198 = /5e25477af34314dc8fd4fe2013845ec55572ac213148b70499b928bc4af1f1c1/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string199 = /5e3261026ae988a6e7d629e1201733ea922d06b37d4d07df2223a1427ea8c63c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string200 = /5fb9f7c101e98f3fd5c011f47519f007fe5d19decf1ade2d36ed57f378b29042/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string201 = /5fd654e8009f29c4f0137c797678d68065bb7a987a70a4437c99623de13d43f7/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string202 = /5fffcdd337374e2843c7582b798b983785da5ab3afb6e30b78cef4620d248b09/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string203 = /602ca6be5b05c2a3d9ed9e038ce1fb3d030cc09cc5038ce751d0eeb3041f1f6a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string204 = /614b2740412e8c02cf6d98cbda2c73f35073967ab26398c30ed2b8dd3d1fd619/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string205 = /643e677418a7b03b82f340efb76cdb2dad8c63dca5f14b653b0b2d89376dced5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string206 = /6537990787752bff7e69cbd253886150278fe24c7aa008a74548d0f09b11d936/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string207 = /65870fa19a49b230121166915868f5dfa7f821ed376ffaef3b181c7669c21474/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string208 = /6690cb6d6fa47260c2cf4ac43b64d2d46e7a7ae4f8d0f10f4fce5d423a1dacad/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string209 = /6975b175e41c894651afbb12b63a2254a405875733c348c204ca96b2fb81790d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string210 = /6a0271fa021d2854ea36531869d30a75d6ee7ff31a521e22e9b382ef1c545882/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string211 = /6ab1c97d28cd80efc5b8698646098879e52c927b7096989b505380e5e6f3b24b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string212 = /6ac9d19e7e7f05803c114b0a76b881f3536d1cc85198f1129d75a91c5efa6aa8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string213 = /6c76fa94d001c749451ec29cb1ff39612c99eb3a06b81a043da5284d37a9dbed/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string214 = /6d1e90be1c1fdcc12ccf00d729b42d5f028ea8bd6f372fa1075e43fe4ef506a6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string215 = /6e142c61b60e8590454a4ce20a8190bf07119ad5843457c9a46205ebea284fb3/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string216 = /6ec665b1a7a7d7a63f8c92469d8bdd3365a8b98fe5f8093112cdfe2887a3a9c2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string217 = /6ee5c663c74ab36046c1648d2ccc825c67e5d0104da08152d3d49f3482499567/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string218 = /6fc0604bf7430b36c6c3e98132f6b708e384581e005fd920da483b5bd2da3cb4/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string219 = /70b5a24ffc45a0c4eadd31d0e202ec9059efc0f0881a50c28ca8ebc2504685e7/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string220 = /70c7134c48911888f49f438586cde06c5da2d333921164a540935c25b612fcc6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string221 = /70f7957d5aafdfe4655ae31e786310395b301e570e75e91c136d0b142f5024b6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string222 = /7111362ec699a575cc5bec3f2e6c4b29b97c42704456ddd00c519e7613b9b67b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string223 = /72324d0492f79682a741e82343a6535c07a0b2f95fcbf592fc80b242b41abfbb/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string224 = /743311db70cca9995302b8033669c33560debfe7f1ba581a92d3aa02c27856fe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string225 = /745d105a0ce33f13d32c65e383e0c8a3e2446b5d279008fe1665737bbc8a6b18/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string226 = /75b44f98a090124d3b41ff610e5e10af410c5161c6a746703123a62a20854139/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string227 = /75e74ba8d2f24a1c4d0543fe9eb5476cfab3b433073412337b6806669a295fce/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string228 = /767ba8f7f88dcc0b5488ca7c93a5e29a7a6ed3195b8ac4027e0108db0ff2805d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string229 = /76d92b0b8c428610081a7c45645612af9a7309cafd971a366d5992f5654f5f51/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string230 = /778b2aafed8b0255a30082314f27182bb6f88c3aed0ecbda92aa092515acf955/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string231 = /787695c6fb15d43a120150628c8d0717983a797682b76106984d717379ccaed0/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string232 = /78bbfbd2d6f42dad63fe000ec04b0c74bd35270b2cc5765404f5c780fe398f88/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string233 = /7c9a67abf328fddbc0cac8484a4f40f0c10e4b9b1cc3d4da6504df1303d7bdc0/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string234 = /7dc9dc828a34eddb7080c9f01c7d6a7ceb6d4f4c876eb48191e741a6af21aa2b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string235 = /7e3763413eb0fd5cd4a0e4d9c90e37cc7325ba05ffec2487fd32a3a7ec0e8137/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string236 = /80230cc6c13af45f3e6a03afdb2ec31b219893ee2da3ffd2da78317e807741d5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string237 = /80be0f50a66761674611885cf41fc742eb8291db9885ff5a08d5867ae74eac7b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string238 = /815533317285b5d53ee050a757d529072b9311106b24f03c79e379109718f84a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string239 = /82b60e805fb8886732eedb461ae540482335cdaf0b3296e8388cbf416371e194/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string240 = /84276ef1f62be4767fa91b3fe35f58b9a1d4e291415723346dd090a85d668289/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string241 = /84b50a32ee55280e0f5c68a772b25b3efa489125f75057b03ec31156c19b4041/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string242 = /84d92157948ff717a224b4dd81ceae8e300b9b363293d6417da97925b4c59ba9/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string243 = /85474d2a885a2dbe2dfd334d9d25fbf1079c1d88c857428e2e1cf3e59f2c0a9b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string244 = /861c5434860a97737943516d0e93e91f5484c8ea557672763ab55bb8c4bbc979/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string245 = /865c9da731e9dedc483277985a51af9ef08f736e512447233ac4bec008539443/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string246 = /8879933fd0c682fa48bfa79023b5730f6ee8e984e8cde1b275a64b098473e424/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string247 = /89eab8092b36ec3ea05291a614742f9f926685f89c2b25fd5804974292255b3b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string248 = /8a417e475065810997e9920df3b411696a4d494abb4204921fd6cb54ff455daa/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string249 = /8a586d7528567dec07746cd375daf9cf8828abee9806fda6125d73323d4fbee4/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string250 = /8b30d6cf12fb57cfd41dd6a41b5f16b04642a019ae57074a4f884a8d5f97699c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string251 = /8b4da3fc66c36752ab032c8d57a0df7caa530d07c3e9847582ff2d792768ff12/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string252 = /8ba2d0dc05dc4a81e064e9bf70eb3681f661b026c7daec1433fb8dad4b9d8a1f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string253 = /8c7bda923eb22fbe0961f2bb9585ceaac8e0c447116ec87979ae44b6a2699ac1/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string254 = /8d0dac6d636eb3acfab0fd50442a8d404251266bcaf175eb4c119917e7ba32bc/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string255 = /8e029c31e7cbb4c481a10a27514bbaf746323fc251c002d132eaf374aae26206/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string256 = /90bb2613b2c711e20dce52480e998feda6e8488017e6f792b486616529cad8b2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string257 = /90dfb88b36bbfab99ffae972aaf0d1959fd7729b11e7b5933486cd2848270fd6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string258 = /9188fe2a96fbb147f85f455cb4edad4f21878e269f032556da95e8d0a9889f93/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string259 = /9250bff8ddad6b9cd10ef94589c2fb82e97a12772856e92af4ff26adfbc3021c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string260 = /932e9575f1cda389162af613cfad2ec48f9fedd7039e09aec2b349ca2a9f663e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string261 = /93c574a4f1608cb5ecf7173e42d35c5a670c58c635e6a90252cd9a102d24e260/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string262 = /93e193e3081c5ac744e40c81c32992ef449c855752d8b10f6483a969950572a4/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string263 = /93f5019c2c7b3a946f3a137fa1754576400c126f24b424076c9801e8f67441fd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string264 = /95494fd45d6bc11bc49f1e41af352f896b7ada9c5eadeb029d6463def8bd60cd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string265 = /95650a1f11040590015b106d08d5453b09acdb02484ddce02f929953ca8a7149/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string266 = /97d1243475c5ef51df1ff21894d4e586742855c345e10938adcdfaf9dbb9a147/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string267 = /983d8e01186ca136d8543a244c21ade3f938d5c51ac610a14c37230a9f123c61/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string268 = /98f65ce7ce360459e9b05b8082d13b27a37efaf63213f80a89b2e22a6a0c38ea/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string269 = /996b73993b6dfdb1d34ab51c5c36dbae12cae353cfab25cbf14b6d974613cdef/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string270 = /996e7473634a2b894f6e154073d780b12f9ef1b8f1471bb945c7c2cf1c56010a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string271 = /997969303538ff70c0e90e33789b0ef3da25556349c7017aac86dd1ad3b9264d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string272 = /9c5b464168986c09b7013338cefd19b006468e8dd677a3bf8e6c9477dd6cee02/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string273 = /9c7acf514e0444e5b30f506a295f7dc65b4a673dd9dbb9ca1558a612105be630/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string274 = /9ceea502f209095ccb4973a18078869931c6b635540f7315d8eccf75055d6f03/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string275 = /9d4774352f398cefc5f715559b274007b59768bd6d1684f7a71d3cc2529097c6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string276 = /9d554dae02fa230c3c36b0014f0703b17afdf57a348083472f70688fb44eb912/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string277 = /9dc8078d3dbaf1fb1ca922f81df33cc871fef0a2dbe271a6756f9fcc0b6186b7/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string278 = /9e1d32bf24ad4bd2def2368e1442237e0a1cc552b7b1fab4ca491b929141dd13/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string279 = /9f42af7c49f77e716869186e182bee63348dd63dc9f407e08f0ff930a5e5b9db/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string280 = /a08b192f7e3409689c1e8c09dab2093623632dd3fae39b56f6eb85ccd72f3f1d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string281 = /a0e67820a910a6441635cb9b663494bc7b0b72c5d81079f14092a3017c5e9739/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string282 = /a129c27027fde0ed374443a6ee7282694e44b670e00cf13b8771fcbc01174cd7/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string283 = /a25b9df135c7a09348526cb0ffdd1e486b7cc6c16df811d83ef1d5402ec1f8ad/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string284 = /a2d412b6feac0c34d148158e5791940e5060bf4b9e6db33e7c444bf715553dc6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string285 = /a3afae22698d3cb4d3f9fff03a42ccf61b3666bd6ef5c455ce6488b6788883a3/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string286 = /a52770362aceeca8d893ccb0fcfdf76991a94dc3e9cac0e595c897d1392dcaac/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string287 = /a650ad2f9d7d9ee450f8fd0926b0ec9512d02f2fbd96f4338549f5064519f9e6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string288 = /a8f27cc54021b10a9a24bde9dd4b569c2394aa7ad1ca70410959e8abf059eceb/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string289 = /a98d565ced4a422049d3ff0ad22e9641af814a09187d5793b40899865733df99/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string290 = /aaec79f0e98582cc0ae90fa4fc34f134454cd4be0ff4cd3e5078f20b516dc669/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string291 = /ab2aacb4caeafc909c788a9ca3cf03202b4f8a6f47dfa759975ac819652fbae4/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string292 = /ab3fe5644df233ee6c10e09e60c7d8a7fa77aeb9eea8c99fd2a337f28e760258/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string293 = /abeda25578952d37a4fdf1814b55799bc99ebd54643fa7608c34750832deb425/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string294 = /ac22d31fa6c3525c62ae4c2536d27ef042d37a23a76691519bfd72671d313fef/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string295 = /ac6ffecbe45068d2dad0314da15f3b193eef94fd005d24646ed246d69bbb6782/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string296 = /ac924e7efddd20c4d783e7a0a30d6d8925f5a077b9450a49bed32a0b0bb255fd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string297 = /ad1117e7a6d3284f9ddc7f8ec841f72b759932d1467cffd9633af242f8f00798/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string298 = /add0626b999fe41981a9f6fbf0e5ee1bc51e4677397e8b8c69cc7a2d36571a4c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string299 = /ae0c6e80d9f3f42919797ee71830ead3490530bdabc1baaa6e5990115bf54d16/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string300 = /ae17da575c55344775eb7b9d6d429265097a5bc90392862e0daea221e983d5fe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string301 = /ae19fadd759b7d9bd55fb0aebf9c903d129f9ca13c0240c7b1dc53c0c934fe14/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string302 = /ae205d0552b3a1a407d43025a1b85de9de6c9edaf7690aae3ef8ca03b07ec4a9/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string303 = /ae8edae460f24e270ff7a2ce2d3b7b126b943f086c5d009ece13fdebd64d5102/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string304 = /afabb213499036eb1aa379aa91c62bedb75f085dd3962b90638a65bea1fc5d25/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string305 = /afe0e8f105e3f0e7eed041cf68a15594aa33a946d27c63adb18b8200ca98e5e8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string306 = /afeb282bb991650ada2e73c65ed5a1770e1a3bc415b2e1e07462b854c077c93d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string307 = /amsi\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string308 = /armory\sinstall\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string309 = /armory\sinstall\s\.net\-execute/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string310 = /armory\sinstall\s\.net\-pivot/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string311 = /armory\sinstall\s\.net\-recon/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string312 = /armory\sinstall\ssituational\-awareness/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string313 = /armory\sinstall\swindows\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string314 = /armory\sinstall\swindows\-pivot/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string315 = /b1f74fb000e49de96f3033358eda1093459f2ea51d2dfbeddb10702af6037a1e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string316 = /b2588fa22ae0bd9b55a88a5b10f81a5fc684c455b6a285417050aaa8dbb2406b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string317 = /b3917dd81417aa8ed07f4a60b34853ea6fae2710a3b5812da455328e38b9e7e6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string318 = /b3a068eaaaefa3f21836c4628ad89fcf8cb20cdb22bc7a188e0b9be9aa29a9c3/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string319 = /b4153afec8b3aa55877961a3cd2bb34defdd8cfb9524620cb640750d08e304ea/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string320 = /b4e643fed3f93eaeb38e615b97041ca7317df9c6e177da9e77e718bb559004bd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string321 = /b54b60bac7b606297627c36b551aa0dfb1291a73175e98da76014e36839049cd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string322 = /b5d812b7f5a4a7a3dcb7a2406ce0e9ea3d247179acdf3e2f69124786bc3205c8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string323 = /b5e23007cc2853e15b55346a3e3088eabdeeab5e61834efe7852b04f0d201455/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string324 = /B64_ENCODED_PAYLOAD_UUID/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string325 = /b7c6bdd822f8710858ed799df49b711001e35901e24ba1726b71987d83cf3e76/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string326 = /b7c6d0220856790482d617170609b3fb76dfbcf7aaa97dac70767e7896151d86/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string327 = /b7f9eb0a95f3523aee8363c59e26a88bcf30d2160db862d4d167945ad342d777/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string328 = /b83141462b74d6d62282551eb34d139eb5c3071516f670af42c1dcc30d6547b2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string329 = /b83bd9409f469f3b094b81bdbf548e5449357ecd4c604d45f3ccd59c02e28a1e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string330 = /b8ae91971edca5937251c1f9a09ca5eb2c48a98ef4a80187394f2c037bbefb46/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string331 = /b94466ebb0aa74a4b4b35da803416e130db2826ee1d0b4191f88c8d602cf4443/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string332 = /ba81b4c4203d94358c4b0b725b4f905ddfb9b4edea7ad6e097d770485e5a8679/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string333 = /ba9660f0473b88e967d6eaeff0671afb20617fe49fe028a4d543e42edd0a8476/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string334 = /badb9d26cebe5c75a4d2ebf557af9496d7acc8a4b5b51f8ef2e686710bcab359/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string335 = /bb94dc4cb2b8a99594a2199912c675406ae64d5e30141c4f3aa9109053a2790d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string336 = /bb95177747c3f54ff72dbcd2942c2278ee7567a1202c6d5c3183faeb78cf673c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string337 = /bbb23c2b1443945e653b67353906939549ffac7dcdcf4bfd6a6c2f67a6320d13/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string338 = /bc7a70c2b56c5e036a0750ab7c93511235161e84f913f538d5e12882b66d965a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string339 = /bd514bc9dda0863e30e834afcf4d5b406c228f10a980ad3f434867d5aa6ef592/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string340 = /bd63af36618538f67b2bf90652fb7536b40c915b307a69887df67bd5cf0400b6/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string341 = /be9bee58f25350d6047bcb9de5b38957d7591c7b048ddd0a2e69162252516a54/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string342 = /bf775ff84feda3935567eef986049ee3049f4533482594de7258eed927c7a270/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string343 = /bfb8f5783cc99fc57d9f2bc9f16229a6a0412017a5c215e0c76d70dd72ed7ce1/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string344 = /BishopFox\/sliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string345 = /c070900d71a49302a7c0db6f075b353e46fa8730050ad0e03054d9999a7bf00f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string346 = /c0cd3083f7015a42a6ceeaed3a49d889e899a1fb751fa952300e6f12669c0e4d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string347 = /c34330f0c27945471126e4ceac5ccea50d2d47584bbc3252351aeff4dd40400e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string348 = /c3a9123c48f1c7024efc87373bf3471e9ee2e5dcdddce594764f21d3123f9cbd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string349 = /c3e38acce6f3bca15fac349fd9f7eb41aa415a76fdf150bd0e75bc096467402f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string350 = /c4ae18df3ccf102f9ae58af818678b96adb1fdc581ffc6625367ffeda420a33f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string351 = /c53bc13170b9ff26b0cca93715e947318e06cafe0d98cf825eabffe3c7f763cb/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string352 = /c60fd707d75bddb69967290cc46c2acf53ffd76899f1cda2f88be8165a25bb1c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string353 = /c63738e628229ff8c8611bac4d15f1cd87fd58c88071765e147d1a50c56d37a2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string354 = /c6a9c538cf33c226c5ff0d37557c0d7d59c62bf37a2765fa090c1ee962edf02d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string355 = /c6aa399c903df33b37acf2e4d8a1e7f514d4e09f046e50dfe5efdb980cf34c16/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string356 = /c7c0c7e68bcc0ce7fbb15505434740e0528ab1240eeb8c3a123c3d84b8f6eefa/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string357 = /c80284ccc6e7c2dab2845923cf4eb2eb02b87292df93f65fd1c54ec726b537fc/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string358 = /c83cac1c4228e554b93ead6aa834427b52f420dd0beda7d7130dbf565fc3ee14/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string359 = /c8c738978ad5131ed15b42f0609008d63513a4b402798b1de20941f4a5993219/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string360 = /c922f6e29c844d15946890f4872230dd9469dd0cce084e913a8df3ef3ea5d126/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string361 = /c9f72eb2e307e3a7689a46f5e2e6c87bfe8f76c977b37e689b4ff3b1895b731e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string362 = /ca3227c4d833b341752927a08d6b41f0c3c81c03f41827859ecff6d008d45172/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string363 = /ca39c3b109987159e58bfa9feb0978f376837f177b1d3b19b49ce29e4d72d90a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string364 = /cac03f25496480d919c18f2eae0bcbe2f80444345bbea088c7b61eddd3c0c152/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string365 = /cb0bdce759cc157371559d3a570630af5bc64c050a7cc79ef95062d3d0db987e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string366 = /cb3754f82aa212d4875c36e00ee5cdbb84f35250b08f019f8b30a2027e00a0bf/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string367 = /cb4272e5aeafc2ee72b02f1f80818ff10214156ed4b8a4ecf12730b13e9a6fd9/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string368 = /cb93e410d0d8660c4aef3b7f98c08408d3ca972b898705d681d9a569b61c703b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string369 = /ccea30c929a2846362b054a4692f6ea16c077b8860080b31245b15e12b27e5fb/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string370 = /cd368574698bcb3e3846833badff06b3e0d3799c2f371d029a60403f0f270f5a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string371 = /ce189906ea564b5bd6d924791d90b65a3c56d4313d45bdab310145e55a042b6f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string372 = /ce2e6ef4cc10bd9de836c9de164dd80e043d713ef1ee3425b5bc29f4c7c6e39e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string373 = /ce75590d1d79bc808d98b70ec03355d1117ca54c3b49b6ba474aa704ea9a6c2e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string374 = /cf9093662998386beaec51633ada8314d43b63904a3eb51e0a9096586b25ee95/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string375 = /cfcdad4c34f652853a157b3f5bf9f8748b5f74963ca41f32632bbd755c250882/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string376 = /chrome\-dump\.dll/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string377 = /chrome\-dump\.x86\.dll/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string378 = /COFFLoader\.x64\.dll/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string379 = /COFFLoader\.x86\.dll/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string380 = /coreImplantFlags\sbinds\sall\sflags\scommon\sto\sall\ssliver\simplant\stypes/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string381 = /cursed\schrome/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string382 = /cursed\scookies/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string383 = /d27b61fa43a50888d967bd4fcc32e9c760086b4240a790561084298238be16ee/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string384 = /d3074edd15856a4138978c24a2b4ba70f6a84abee3db440a710e6b8a2fd597d8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string385 = /d4d82865304b28c413e0127789f79a4dc49a498782f840b3e2421e8429c66391/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string386 = /d5743f7c28385bcb3b4a07eabd2a49a3791f5b0a929b60c50700cadac1451da8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string387 = /d80e2a137e1d2639c8e689549e5e17423f7ff19aa0bbfcab8e75b43c6c4b2d60/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string388 = /d87c78f071b72de76e3569729f5dce81b6379a9ef115a5e4305e1e089531938e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string389 = /d8982f57fd89ad996df4e3abe1610118575d8ae93f06cc2564c230d1c5f99d36/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string390 = /da23cfa752e49e813f9b47639456b433cbbdd0e4e50f4d0647c653ecce17ab97/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string391 = /dac48d1f87a5d34496182771b76988929cc81463c576110b866165902f30b3bf/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string392 = /db15d8f9e04fd3d793065e806b32df940949676a7b5013be10b1285fd4cd5676/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string393 = /dbd58dba5d92e8d7b6c8dfc6fc54185c33ef8442c61e02f4448bf9641643e596/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string394 = /dcd82c989816c886bbe27741b2bece34a7bf4a1a9a34abfb9b34fe3cf9484201/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string395 = /dd9203bd24970aceaa30d3241a10fd259380144e57a279021b4c4378fa6c5922/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string396 = /de0565be5697d5543b8abb888a6d3d94d7cfb2538500b74ee38010f54f96a96a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string397 = /e0dc49ab46ab388ae93213602843e135bae218d15f17fc74bdc56de38fe5d6cc/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string398 = /e12b5b70989233ee34a1984b959ac4e42a282148cc0f6f8a5434f2a1502e3fdd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string399 = /e1a068365245f8a021fca5f8b40a2cc5aedd235015c39db6697b7d3ba05cd996/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string400 = /e27f5050d889525c51431074c81403d6917f081af8694a978e92a975a5b67472/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string401 = /e281c4aeeb508f9ec7abdaedde54203747ef31b02b97aa21ea7a2c4c06659f11/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string402 = /e32a0a69f8d98f79823aa087f883b16e04b4993090aedc0e29ca11b571e1bc4d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string403 = /e3a6fd1ebf5912045e94cbe9cf44ec388351c89aab2054a647332e41f70f27df/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string404 = /e3a9b1c8dfe7bfcebd4d908f7cc36df8d09ee579ab10738308f0536782a14fe2/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string405 = /e43289578251611f4f6f9952fa6ec598ed69b71c60ddc9077e69495fce018838/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string406 = /e45f0bbbeee0fc901b50a0034dbeee8a1f2fe8b60ac58309580b3f7659dd9784/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string407 = /e50bd0143399ca09e3a293f2546cdacb0bf093294dda39263474ed55d8e1743d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string408 = /e59ca634fa9b25563346bcb14e9e97d40dbfacc3159291aae5b104e99caede32/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string409 = /e5c8fd6cca1c71cb4302024e18e2ffb1d2cb00b583f391368adb5a73b803e3b0/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string410 = /e6ea547331fd4daf15426484f27c256d680bca82d911c038ec1e1b97e1a2e14e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string411 = /e793dfecc85224131dd071a5ff7b9ea7c01156879879701951152090bab15ac5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string412 = /e86f3bf9daab62a33014d63811a020cab6ebb0570a8cea4496b1ee586ad6c5bd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string413 = /e96e826e534e4ed95244cfdb1147d13b3805c46468be98ed540be2fab68d586d/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string414 = /eaae77ff59bd46d07499b29eaefb4ba3f1d1e36fe3c99ab46bb1fd578113cbe5/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string415 = /eba7e3def98ff4fe742daf4b2caf56d74fb83b502fc035753646fd5fd115a402/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string416 = /eca525adef0c1dae7233b25f241c19cddbe8683cbbadd7c69915f7b3c37fb21f/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string417 = /ed09e2c53b898d79b81b5aa96dfc9b5ed696b34491eef7b5fefe9fb7ed1cbaaa/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string418 = /ed68e081f359726e140c31e96c92da4aa363a976569f4f9357f73f738d534dd3/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string419 = /ed85a47316a693661dd964ef58efb31bbe5ed97d2f9560021a220bbb912a9c2c/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string420 = /ef377470d920bdd421679da6fa7dd8a4cd7445b22db2829419dd62be97131583/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string421 = /ef62b7afc565b06ed3c0a764f927ce9ccdc376c569c74c4c8ff1c977d89ef15e/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string422 = /etw\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string423 = /f15785e3f3b824872a6b9dd8c550886179d3e636f0f1939d2b45c411701c72f8/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string424 = /f1c6a2f008eb7888b5b081a834088a4a1b6fd688db3c99c89541d673489ae130/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string425 = /f4309ce07f27a76e253734d7b4b99159aad92445dd653b5dd96e3e76c9905588/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string426 = /f5e85e80a5eb0184e26a3339871e5a5d0d4db497395f91c8305c018c51040912/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string427 = /f7353868e1e35feb2bbd3a1b478698217a4cd06679fdb5dc8cc90f5232caa94b/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string428 = /f82cb120b7c3c7ef03c656790fa81118e5e6cab286c458bdcc45220bbc5507dd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string429 = /f86331a57befd87e3ea359578a7a8b526d924dd11cf629ce1f24f2626d107928/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string430 = /f8a705f52d2b4587dfbf680d12d4b1af6d5ed91872257a756e2d5f4bdee24c45/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string431 = /fa1d33fe72c69de384fe29f15ba46074e8c4b1a0a7e884fb0dddde4149775f08/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string432 = /fcc29a4c87c77c17f93c5b4703d34a4d94ee2f6b66dc149e539978c7cb4924ac/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string433 = /fd13ae5d3ace637c564434554f669a30cd5d527c918d1681c856e62f2a4dea85/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string434 = /fd735c976b71fe21f1f35dca8977865e69e4bb3a49ffb7c64c65d3a235d237a4/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string435 = /fdeb5626b8c7d92daf188d05564398134d3dd50c9d1d2b09352a5d5a0d2757ee/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string436 = /generate\sbeacon\s\-\-http\s.{0,1000}\.onion\s\-\-proxy\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string437 = /generate\sbeacon\s\-\-mtls\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string438 = /generate\s\-\-http\shttp/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string439 = /generate\s\-\-mtls\s.{0,1000}\s\-\-os\swindows\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string440 = /generate\s\-\-mtls\s.{0,1000}\s\-\-save\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string441 = /generate\s\-\-tcp\-pivot\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string442 = /generate\/canaries\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string443 = /generate\/implants\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string444 = /Generating\ssliver\sbinary\sfor\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string445 = /github\.com\/bishopfox\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string446 = /http\-c2_test\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string447 = /https\:\/\/sliver\.sh\/install/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string448 = /implant\/sliver\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string449 = /inject\-amsi\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string450 = /inject\-etw\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string451 = /install\sc2tc\-domaininfo/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string452 = /kick\-operator\s\-n\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string453 = /leaky\/leakbuf\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string454 = /MIGkAgEBBDBido1KtKSwQah\/WIoGkDZDX2WPXdexUVAmi0tf6Pd9vK5pfpt2II/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string455 = /NewConsole\screates\sthe\ssliver\sclient\s\(and\sconsole\)/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string456 = /new\-operator\s\-\-name\s.{0,1000}\s\-\-lhost\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string457 = /pivots\/named\-pipe_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string458 = /portfwd\sadd\s\-\-bind\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string459 = /portfwd\sadd\s\-r\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string460 = /priv\/priv_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string461 = /procdump\/dump_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string462 = /profiles\sgenerate\s\-\-save\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string463 = /profiles\snew\sbeacon\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string464 = /profiles\snew\s\-\-mtls\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string465 = /raw_keylogger\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string466 = /raw_keylogger\.tar\.gz/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string467 = /rpc\-backdoor\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string468 = /rpc\-beacons\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string469 = /rpc\-hijack\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string470 = /rpc\-kill\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string471 = /rpc\-msf\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string472 = /rpc\-shellcode\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string473 = /rportfwd\sadd\s\-r\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string474 = /Sending\smsf\spayload\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string475 = /silver.{0,1000}\/beacon\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string476 = /silver.{0,1000}implant\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string477 = /Sliver\sC2\sSession/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string478 = /Sliver\simplant/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string479 = /sliver\.service/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string480 = /sliver\.sh\/install/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string481 = /sliver\/\.sliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string482 = /sliver\:sliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string483 = /sliver_pcap_parser\.py/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string484 = /sliver\-bof\-dev\-quickstart\.md/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string485 = /sliver\-client\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string486 = /sliver\-client\.log/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string487 = /sliver\-client_linux/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string488 = /sliver\-client_macos/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string489 = /sliver\-client_windows\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string490 = /sliver\-dns/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string491 = /SliverKeylogger/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string492 = /sliverpb/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string493 = /sliverpb\.Download/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string494 = /sliverpb\.Services/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string495 = /sliverpb\.Shell/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string496 = /sliver\-server\sdaemon/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string497 = /sliver\-server\sdaemon/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string498 = /sliver\-server\soperator\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string499 = /sliver\-server\sunpack\s\-\-force/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string500 = /sliver\-server\./ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string501 = /sliver\-server\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string502 = /sliver\-server\-linux\.zip/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string503 = /sliver\-server\-macos\.zip/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string504 = /sliver\-server\-windows\.zip/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string505 = /StageListenerCmd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string506 = /Successfully\sconnected\sto\ssliver\slistener/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string507 = /systemctl\sstart\ssliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string508 = /testing.{0,1000}\stesting.{0,1000}\s1.{0,1000}\s2.{0,1000}\s3\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string509 = /The\simplant\scommand\sallows\susers\sto\srun\scommands\son\sslivers\sfrom\stheir/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string510 = /UseBeaconCmd/ nocase ascii wide

    condition:
        any of them
}
