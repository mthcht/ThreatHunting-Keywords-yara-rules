rule shadowsocks
{
    meta:
        description = "Detection patterns for the tool 'shadowsocks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shadowsocks"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string1 = /\sinstall\sshadowsocks\-rust/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string2 = /\sprivoxy\.exe/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string3 = /\sshadowsocks\-divert/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string4 = /\sshadowsocks\-rust\.sslocal\-daemon/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string5 = /\sshadowsocks\-tproxy\-mark/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string6 = /\/etc\/capabilities\/shadowsocks\.json/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string7 = /\/etc\/shadowsocks\-rust/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string8 = /\/genacl_proxy_gfw_bypass_china_ip\.py/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string9 = /\/privoxy\.exe/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string10 = /\/Shadowsocks\-.{0,1000}\.zip/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string11 = /\/Shadowsocks\.zip/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string12 = /\/shadowsocks_service\./ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string13 = /\/shadowsocks\-manager\.sock/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string14 = /\/shadowsocks\-rust\.default/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string15 = /\/shadowsocks\-rust\.git/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string16 = /\/shadowsocks\-rust\.init/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string17 = /\/shadowsocks\-rust\.service/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string18 = /\/shadowsocks\-service/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string19 = /\/shadowsocks\-windows\.git/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string20 = /\/usr\/local\/etc\/shadowsocks6\.json/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string21 = /\/var\/log\/shadowsocks/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string22 = /\\genacl_proxy_gfw_bypass_china_ip\.py/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string23 = /\\privoxy\.exe/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string24 = /\\Shadowsocks\-.{0,1000}\.zip/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string25 = /\\Shadowsocks\.CLI\\/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string26 = /\\Shadowsocks\.csproj/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string27 = /\\Shadowsocks\.zip/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string28 = /\\shadowsocks\-windows\.sln/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string29 = /\\ss_privoxy\.log/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string30 = /__PRIVOXY_BIND_IP__/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string31 = /__PRIVOXY_BIND_PORT__/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string32 = /00833ecb01131c0c74ca39cfc0e0fe3549651df916dfc4d2c6d7aeda600784bc/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string33 = /0472497b295c4466e58c2623f2f03281f4a8297696753dd18effe3a4d633e86e/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string34 = /0eaa8e2763861316fdb41ba45636dbb78c1593714a0ed480573ff7efc5b34b7a/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string35 = /13141ae2c7cfeea1ffe619f76b569d4c52204298daf5b986ffd4693534581b1e/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string36 = /14f0840dbabc554d43cf3021e04f7b11c7285bd85ee13dfb9d59c0a942bcd515/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string37 = /1CC6E8A9\-1875\-430C\-B2BB\-F227ACD711B1/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string38 = /261755fa0c132c7719c4c5176bb2b5308a0176dc716fea898d3c63d60a21c521/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string39 = /2654a13a86c8ac23149c8a173eed10965036445c50d53515d67a634b43e4ab87/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string40 = /2731974930b30b2fce237f48911486b45dbd2d896d9ab3347051b0022a8bd424/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string41 = /276d3ecc4dcbd180a4ee953cd9721ced7ecf1309d332b05bf3d0f02bfb73bfee/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string42 = /2cc467b53348d1cafe2d329b96a48fdb54198fca6a6e1cf41b98df353f458e6f/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string43 = /3f2b33ff51dfa3351b72926fc97202f2681af4aa329b815e55100851b02b8896/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string44 = /46143050aa4cea03129c03b45faacccaa3773f2d7f300f7f031ffb83de547cbf/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string45 = /4a302071d7fc21367f31e0d9c5f77ef1eb41ec097eaeadb8d65472b6be55ab99/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string46 = /4acb4274db08c54c943eef6f456c6913557163d203cbd8be63a6780e5dcf7a42/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string47 = /4b7786288011e1255695cdae0c2199353203fd94c2c6fa57bc3be3d332344c6a/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string48 = /4d75006597652c67dc56aa9a078eeca3a52634bf1bf591b68c926bd01ad53d25/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string49 = /4f932e61afb6bd1dd8b5c4c25c715f1623d3f574637d8154256531b4ef5000ac/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string50 = /5bb545bf51618a253b1ccc145bf97c8ab29d9118d6ac5e90b9bfc33bb988c3d7/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string51 = /62786ba330d6b4969906b297fbb26c3f9a9ad36672b4600938d3b607e9b3c980/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string52 = /62b74a688d22bfdf20f673a351580029d7b9de67c6facc9a5613b22b3f798968/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string53 = /662f875055d740d98e0047adeb2b632b85cafffa2129c1635c5312217ca978f3/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string54 = /69c2084081bcd8ea91474bc4292863af35bdafa0b3e3b585195bdb0e0523a419/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string55 = /6a842f64b5e04384ef3a1cb19797f2aa714ab44b3320f132529c60f4aafc6d75/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string56 = /6c8aefae3e5ece28c1e182ffec2c00baf2faa7ca61c426b1db6275b03524dc8d/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string57 = /6e2028eb0bc06325c6101c497832e66a95ce482b1771455bc7a873ef22291c65/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string58 = /7749bb3fa881d702bdcaf541f87308c438663ef32fc67c07d0c10c286f7da12f/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string59 = /78EB3006\-81B0\-4C13\-9B80\-E91766874A57/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string60 = /7a52b4827a4dac14ccd0c8a05a46c7debafca33672285e7630ee8f8e54387738/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string61 = /81257d02ae9cd6d59809ea470ce590cdeb3e7949f5a51dfacba21e1cd3d2713e/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string62 = /83c2966fe942b2b0a1e31ea84f6336c024cb57ff5c397b0d1cddf050bb4e5b21/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string63 = /8455f37f4777a237e87e3326cc9dd7af51b3bc2cfe968ff488e85effb2ca30ac/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string64 = /87907a6d7e8d6b4cdf4264950869799096b5ebc9c3de4c9ed0204d91650ed54e/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string65 = /8923E1ED\-2594\-4668\-A4FA\-DC2CFF7EA1CA/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string66 = /8bd3acb166ddf194c57b5a38af0c9b3d1a60ab623fd04efa94434dcf5bb787c8/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string67 = /913a779a64c4488167dd4d0e43427498ac2bb64b63ad6075b38c5c4af4f2e768/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string68 = /94DE5045\-4D09\-437B\-BDE3\-679FCAF07A2D/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string69 = /9509da528a842ad647f557e84ec00afbaf345222bf7d6219031bf176e4bba80e/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string70 = /97C056B0\-2AEB\-4467\-AAC9\-E0FE0639BA9E/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string71 = /97c1afbdfbe31e7fed17143d9885be6588be294488cffc83661a5ef55655d3d2/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string72 = /99142A50\-E046\-4F18\-9C52\-9855ABADA9B3/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string73 = /a44ba10f3e101f1118ea65ff2272e1b2da2d0ac96ceb0043bf3c9c75ad4a53a7/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string74 = /a5e9856fc84492bf129cca06659842ccc9705f7e24eaa9bd6ec5d529f7c61abb/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string75 = /a9b64e47ef85ace30ca6ea6e9d79fdc665a7eb7b0a4763a659f00aa307cf7ad5/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string76 = /AE81B416\-FBC4\-4F88\-9EFC\-D07D8789355F/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string77 = /b4810eb33bbc3888e66d51db3c76a52abe7b98d8520584daa8d92c03e412be57/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string78 = /b5df12aab758bbaea8291069515a6e46b84b7b5326f24d54410fa20ac8c0c447/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string79 = /b6d55d6536ff5e827c393516158924d228cfc2de2d127e302537e0f4abf1f98f/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string80 = /ba5e8ac5fc350cef4640480e48932359266bff6a2a85fff3a9163dc07e5a310b/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string81 = /cab2848992b779a1bdcdf76553265dc73b70046442ec9949135a515f7b65819f/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string82 = /d19215f26a1791d5f04cd626f65108628e507be6df194fec4fe25115d74469ab/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string83 = /d39f61dbf2a753769c0efb7712dd7bfa6e1d1593ebaed06150f206f3b6ff7de2/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string84 = /DFE11C77\-62FA\-4011\-8398\-38626C02E382/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string85 = /e1f6be0e39290a73ebd45a3f6254015badf0f451307ded5d96d2a3acb91e0642/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string86 = /e3584150cc2cc74f7582e84f91ae9c258e63b67e722b0219a6378212c03ee85a/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string87 = /e6225af4ab483e49445f0021bc05efc405e544e7a725eb6ecb3f8777a8783109/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string88 = /e6fe3c2968b235f58bdd9b5e0d1eefafb1e577c9fc7a533eb88e198d11773b2d/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string89 = /e9fad6bcba22427d7efb3d9b341d11173659a06cc12670ba9d542aeb670284b8/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string90 = /EA1FB2D4\-B5A7\-47A6\-B097\-2F4D29E23010/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string91 = /f3cb648c848b10ea67fe776ed08f1de7258d3e3e4f1b9a5779ecd500de9e9dd0/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string92 = /f5f1aeff01f602aca4aa2da893395b2ae6552325e46ffe31c267ae5494558c8e/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string93 = /F60CD6D5\-4B1C\-4293\-829E\-9C10D21AE8A3/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string94 = /privoxy_UID\.conf/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string95 = /Shadowsocks\sLocal\sService/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string96 = /Shadowsocks\sstarted\sTCP/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string97 = /Shadowsocks\sstarted\sUDP/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string98 = /Shadowsocks\.PAC\./ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string99 = /Shadowsocks\.Protocol/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string100 = /Shadowsocks\.WPF/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string101 = /shadowsocks\/shadowsocks\-rust/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string102 = /shadowsocks\/shadowsocks\-windows/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string103 = /shadowsocks\/ssserver\-rust/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string104 = /SHADOWSOCKS_CONFIG_PATH/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string105 = /SHADOWSOCKS6_CONFIG_PATH/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string106 = /shadowsocks\-local\-service/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string107 = /shadowsocks\-rust\-local\@/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string108 = /shadowsocks\-rust\-server\@/ nocase ascii wide
        // Description: Rust port - shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-rust
        $string109 = /snap\.shadowsocks\-rust\.sslocal\-daemon\.service/ nocase ascii wide
        // Description: shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // Reference: https://github.com/shadowsocks/shadowsocks-windows
        $string110 = /ss_privoxy\.exe/ nocase ascii wide

    condition:
        any of them
}
