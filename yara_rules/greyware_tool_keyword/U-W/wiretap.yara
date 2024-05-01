rule wiretap
{
    meta:
        description = "Detection patterns for the tool 'wiretap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wiretap"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string1 = /\sinstall\swireguard/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string2 = /\sinstall\swireguard\-tools/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string3 = /\spacman\s\-S\swireguard\-tools/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string4 = /\swireguard\-installer\.exe/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string5 = /\swiretap\.exe/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string6 = /\.\/chisel\sclient\s/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string7 = /\.\/wiretap\sremove/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string8 = /\/Wireguard\.zip/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string9 = /\/wireguard\-amd64\-.{0,1000}\.msi/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string10 = /\/wireguard\-installer\.exe/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string11 = /\/wireguard\-installer\.rar/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string12 = /\/wiretap\sadd\sclient/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string13 = /\/wiretap\.conf/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string14 = /\/wiretap\.Dockerfile/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string15 = /\/wiretap\.exe/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string16 = /\/wiretap\.git/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string17 = /\/wiretap\.log/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string18 = /\/wiretap\/releases\/download\// nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string19 = /\/wiretap_.{0,1000}_linux_386\.tar\.gz/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string20 = /\/wiretap_.{0,1000}_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string21 = /\/wiretap_.{0,1000}_linux_arm64\.tar\.gz/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string22 = /\/wiretap_.{0,1000}_linux_armv6\.tar\.gz/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string23 = /\/wiretap_.{0,1000}_windows_386\.tar\.gz/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string24 = /\/wiretap_.{0,1000}_windows_amd64\.tar\.gz/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string25 = /\/wiretap_.{0,1000}_windows_arm64\.tar\.gz/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string26 = /\/wiretap_.{0,1000}_windows_armv6\.tar\.gz/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string27 = /\/wiretap_relay\.conf/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string28 = /\/wiretap_relay_1\.conf/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string29 = /\/wiretap_server\.conf/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string30 = /\/wiretap_server_1\.conf/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string31 = /\\WireGuard\.lnk/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string32 = /\\Wireguard\.zip/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string33 = /\\wireguard\-installer\.exe/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string34 = /\\wireguard\-installer\.rar/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string35 = /\\wiretap\.exe/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string36 = /\\wiretap\.log/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string37 = /\<Data\sName\=\'Product\'\>WireGuard/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string38 = /\>WireGuard\sRelay\</ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string39 = /\>WireGuard\sTunnel\</ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string40 = /\>wireguard\-installer\</ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string41 = /0164502183613e987753f77bf9a45bde5a08f9332cf2d119cbfbf284cae64a25/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string42 = /0183a78b64841b968eac59c0c912ecb0c44ec0ccdd773e422c6529d4e0ea5ca3/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string43 = /071c1ac9622484472732bfb85fdf11bf4a62d70d4f5d2aeed5a92e9e8be51346/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string44 = /072c59c3bc429c761425c680611cc35c189582d6837d4b2bd205c648722b51de/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string45 = /0b3128b7117e4575cd58267525750053b8ad2abbff38d586faa4e2b72c7a31db/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string46 = /0fe131b5d680b328dd8c3286d6c300b0bd606373d3a2de0e6ebec613528bf65d/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string47 = /106be837e5aca74895a290d85bbcf90f95e4613f41de7d28f9fc834d8f34afad/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string48 = /12d9cf76e82ea590777ee552a9ff96a10b6304df20b141bb2dc7bdf054be8402/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string49 = /14ac418b893997f60d07f0b2ce81ac979ec6ba849664de462cef5c6c720e93f3/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string50 = /1c7b04e5a15afed07071240ef6dfda584aede9f24e333463b6e00cdaa3886fc5/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string51 = /1caf54aea406542836d678b35daef36f7dab5c6b271cc9333bf9132fb9a11b5a/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string52 = /256ade9e6d03ca6e485f0932c122dbd226762d2c29c07414d0dc1dcac2a4eb0b/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string53 = /2d042ee6e000dbf50b37b2fe8a77fb8cc71de9b4beb0f6f902b4d0885ae8facf/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string54 = /2d87b8f3d0a56c9e101271c83e0b4c8f243af14a10965619d037210900304dde/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string55 = /35fb32ecde0afcac0b1feb446052674763484264adae6c09148f4a0c7adac433/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string56 = /5141adc9e35e695f849f9f2a7749a428263d1a02e1efdf24547f53596be97a25/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string57 = /64601caa675146be542b3e4c658019f9c443c8fa64a898985aa691eab5c5037d/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string58 = /671eaebafae768f136c85087dca3ecc2068283e611f62345d152d843cfcf02ea/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string59 = /6e44d4eec61c35b14e9e43158b8a169269a98be0e2ae8992cdb0a50ea09b97a1/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string60 = /74ce40c0871314e1308984b12d93161faf806f6d508dd256678f09af1abc1052/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string61 = /7ca32274aad66276fcbc12b50158356781277aa4efc50eee49c10f2eac192cef/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string62 = /831096dedc1741e97c5a65d992cf8825a02bdcd43c76727d2a9d26638cfeedd3/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string63 = /8432faf9d944bcf430ebb7d45282f84901a59eb5e4ae3fc9b7ba5226b7a4ce35/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string64 = /8fcc7cb6eee6a29804ae22281e0477c47de9a924bd7beb9bed24f7c1d84d8a9d/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string65 = /9a6975a16e6abee257353caa0216c7ee50aed1618cb05c73ee105ecd07e0bdf3/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string66 = /a059a3d56743994d8f3996e05725957ebb5099c97bdd8ee92ed739f552073f46/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string67 = /aa660d59e6c7783ebb9d4244d3991392ab602cd4fcd06457656bed2f61b7b51a/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string68 = /b1a6f85aa7693abc888ec5cd0313b16ae5e932dee4e04f495481935530276427/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string69 = /b710bdc87555b125cca39a89d2f41449b99afa567ec7e78f6e28b3f7bf872ac3/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string70 = /c88212e7221a28d2877ba03c01c5df776c61aa4e36bc5a5909bceea7545fdfb1/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string71 = /chisel\sserver\s\-\-port\s/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string72 = /d04679accb8ad4bbd940d7afcb4d2765c3ea1421bb773b71e79f3f0233f847cd/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string73 = /d520c8bd60a9f8da3a90b1b47194dfb17df78554a97de633fda813c0152c01b1/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string74 = /d59838007c4724beca80ad34c6adc749c526f6de636d79e06565499d0e390110/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string75 = /docker\sexec\s\-it\swiretap\-client\-1\sbash/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string76 = /download\.wireguard\.com\/windows\-client\// nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string77 = /eeee2b0a6ad1c7e4614fed4dfbe58b63776f6a3a6758267b5a976b4dc4315f48/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string78 = /f9ddbf1047c9a2e24310e5dc68508504c69e037e47c624f32b4d25ff8b30ed87/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string79 = /fc901b9f783876c3cb057dbed28b5612fd376963f148d1375bb0c8cf86bb2e10/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string80 = /https\:\/\/www\.wireguard\.com\/install/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string81 = /sandialabs\/wiretap/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string82 = /WireGuard\/wireguard\-go/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string83 = /wiretap\sadd\sclient\s\-\-port\s/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string84 = /wiretap\sadd\sserver\s\-\-/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string85 = /wiretap\sconfigure\s\-\-/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string86 = /wiretap\sexpose\s\-\-dynamic/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string87 = /wiretap\sexpose\slist/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string88 = /wiretap\sexpose\s\-\-local\s/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string89 = /wiretap\sserve\s\-f\s/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string90 = /WIRETAP_E2EE_INTERFACE_API/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string91 = /WIRETAP_E2EE_PEER_ENDPOINT/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string92 = /WIRETAP_E2EE_PEER_PUBLICKEY/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string93 = /WIRETAP_RELAY_INTERFACE_IPV4/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string94 = /WIRETAP_RELAY_INTERFACE_IPV6/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string95 = /WIRETAP_RELAY_PEER_ALLOWED/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string96 = /WIRETAP_RELAY_PEER_PUBLICKEY/ nocase ascii wide
        // Description: Wiretap is a transparent - VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
        // Reference: https://github.com/sandialabs/wiretap
        $string97 = /yum\sinstall\s.{0,1000}wireguard\-/ nocase ascii wide

    condition:
        any of them
}
