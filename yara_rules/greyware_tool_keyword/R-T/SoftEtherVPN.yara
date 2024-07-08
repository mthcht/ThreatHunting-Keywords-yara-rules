rule SoftEtherVPN
{
    meta:
        description = "Detection patterns for the tool 'SoftEtherVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SoftEtherVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string1 = /\sinstall\ssoftether5/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string2 = /\sSoftEtherVPN\-.{0,1000}\.tar\.xz/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string3 = /\/libexec\/softether\/vpnserver\/vpnserver/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string4 = /\/SoftEtherVPN\-.{0,1000}\.tar\.xz/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string5 = /\/SoftEtherVPN\.git/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string6 = /\/SoftEtherVPN\/releases\/tag\// nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string7 = /\/softether\-vpnclient\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string8 = /\/softether\-vpnserver\-.{0,1000}\.deb/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string9 = /\/softether\-vpnserver\.service/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string10 = /\/softether\-vpnserver_.{0,1000}\.exe/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string11 = /\/usr\/ports\/security\/softether5/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string12 = /\\AppData\\Local\\Temp\\VPN_.{0,1000}\\VPN_Lock\.dat/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string13 = /\\appdata\\local\\temp\\vpn_.{0,1000}\\vpnsetup\.exe/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string14 = /\\AppData\\Local\\Temp\\VPN_AECD\\/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string15 = /\\CurrentControlSet\\Services\\Neo_VPN/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string16 = /\\CurrentControlSet\\Services\\SEVPNCLIENTDEV/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string17 = /\\DriverDatabase\\DeviceIds\\NeoAdapter_VPN/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string18 = /\\Program\sFiles\s\(x86\)\\SoftEther\sVPN/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string19 = /\\Program\sFiles\\SoftEther\sVPN/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string20 = /\\Public\\Desktop\\SoftEther\sVPN\s/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string21 = /\\SoftEther\sVPN\s.{0,1000}\\client_log\\client_20.{0,1000}\.log/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string22 = /\\SoftEther\sVPN\sClient\sDeveloper\sEdition\\/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string23 = /\\SoftEtherVPN\-.{0,1000}\.tar\.xz/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string24 = /\\SoftEtherVPN_build\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string25 = /\\softether\-vpnclient\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string26 = /\\softether\-vpnserver_.{0,1000}\.exe/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string27 = /\\softether\-vpnserver_vpnbridge\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string28 = /\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SoftEther\sVPN/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string29 = /\\Start\sMenu\\Programs\\StartUp\\SoftEther\sVPN\sClient/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string30 = /\\Uninstall\\softether_sedevvpnclient/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string31 = /\\vpncmgr\.exe/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string32 = /\<SoftEther\sVPN\sProject\sat\sUniversity\sof\sTsukuba\,\sJapan\.\>/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string33 = /\>SoftEther\sVPN\sSetup\s\(Developer\sEdition\)\</ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string34 = /\>SoftEther\sVPN\sSetup\</ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string35 = /00B41CF0\-7AE9\-4542\-9970\-77B312412535/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string36 = /096311de816ac0a5c886680f6e60f99ad60df58773f2dbece09fb35e48b5702c/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string37 = /09b5f413ec7c75c4ad05a832f70512725f706be190b77a04bf459ba46bf4fb1a/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string38 = /0e6ac7f5a2adec8973bcb337c1f12f28931b76f3e3d45b14d63acf1e3bf07a31/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string39 = /115426ae1c906030d369a2d7f37ccdbc059869f709add60b6a8177a8100e7b61/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string40 = /121559209213c1de5bccd241092888985985c6992122e59d1ef053b89d5b9c99/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string41 = /18c7944f13fe80a024cb1fdce6a2621dcd2ab11f639773d42902aec34085b51e/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string42 = /19ee368d7680478dc89a246dbf3e57a05242a239a68d40ec6529208425fbf485/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string43 = /1b14c2ba7ba16b131c65a8e61bddef8db25bec2d641ff138b9a84a522581aff7/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string44 = /20562bf31696728f41152473ae781c24d7a6809ad34c57fc4f8219ddc0d98f47/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string45 = /2222ef48b3f9102265ef7d27e496ad40a1bd1eaba8093bc5e696b48402c52441/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string46 = /27d9a04aeaab3a37b0de7e3976fd928695c3e2488e7b6b8be5d95e8fa1dd8f4a/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string47 = /284fb65de7d9c928ca978cebd863136e79c618d65b357d3da9faeed6008783cb/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string48 = /2a0542f8d159539b07faeb5849be99d1c62e1c16d236178fdc13eb2ebb7b262e/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string49 = /2a7896d5bad2028fec904ac21e4355e0446ad5c9036bd1c3b8b2e93e0646bd6e/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string50 = /2acb885af8fce92b0cca89d8e2b82d954a85f8ce0751a27258a3c4cdd2f8ef88/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string51 = /34b8d45bfea0d60f3b897a8c36276bdfeb7e9b00f0ee673d43f4555baf9eb8b4/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string52 = /381bca8edcf6cb2302baccebc9daada145989116aace489ba3d9072a57a853ed/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string53 = /38b4843755a0ceca33637b4a1bc052b4c379b666e512511c4629ca6a65468bd3/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string54 = /3bef28a58c4ee75b3b4ac0a6025f1c0332bb1d9f27d066082fa2e32416da4eac/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string55 = /3d3deaf15f2bf36dc998286809ee0fa327cb526bd5a93026d8124af3b8d8182b/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string56 = /43d3a9e3e07ebacf08278a47845b29b0c29daac00ae1d6ca7756f47de4a67b7b/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string57 = /447d9a15567f0eb81871ddbdc2de28bd2e339b892548bab25a9f58afbbc177a7/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string58 = /4876b52e363af1705a6c5ccc1c6be930dd47226f4b2835ec827bf8e4de33c40f/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string59 = /498244e2fa32092cfd4b6f2d0b62a8f963724738cd01ed9f623369ff55a309f8/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string60 = /4f42773bb9fa283dc34d4c54347b197b95176024cf3fc6c1e11932f2a56188da/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string61 = /507a32af5f58e47f635053b3ff0605db2e819cd63d31709e40cb1d98364b015b/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string62 = /51a6e79cd5c7e100116719a73c4f005f8b5dc59027adfe75e77d154af938d698/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string63 = /55af645a3111f2f9ecf35df965f709378a72e216d1963c134cade7391c24f563/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string64 = /56930110ad5e21a3b7c69008bdb3efd368c0ebafc1d0d97b48a76a3563ec8e24/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string65 = /57f265c72747a75c914118d2f69550b534d661f49bf8684c81f7ef75c952f97a/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string66 = /5ba980906682ff6eb47a50cb6208901518e62d013ff46075e96a919331dc23b4/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string67 = /5f2cab7fc38140b2cc11a54ab687ab4fb8966ca4965822b8c85025d45a47c0fd/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string68 = /60e0928a261b230fb6fffc711348a4acc1a73a00d95a0060eecd96e9c7c16a82/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string69 = /61dc49f7c5b09a72e96329e43bb3a896c428da449bb67c7803d21eaabd7591b6/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string70 = /626d14d508afc1bcbed6e013d531d64a1c5fac529790857ad2730f6ca864aece/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string71 = /6440ef1a2fab83dfb27e976067134eb5767fbdcf20e7ad73f217b37ce3014eed/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string72 = /6f486fb6576a30179b3ef6bf36ad0bec39745f22d504209abd602338c77707b9/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string73 = /701b8a45901f7dc715140662e68f7d7e8c59f631866f9ac862896cd06a2d5865/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string74 = /744a0029e2e666d09e3fad6304782ceb12997dbaf2b9288caaf8485c80ddf949/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string75 = /7459f321ec957d160f95ccf5fccc46be6f2c26bd78f0bcdf03d53ae131d051f5/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string76 = /78a34aed87a873fb155ca34ec30ec520bf64f34fbe4452be2ba3a8a928a28e30/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string77 = /7b3ed9e4b5430bbfbb619e7367e05319fc41102dba1dd2103a25f37d66dcd1b0/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string78 = /7be4b33d5f554546778d2f4b35cab35ea4157cad14b68cbc730bf4279fe3d3fb/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string79 = /7c437d4d02d7e2a936b4c1ff7bc8f5abbf16786746deffa92d5f5f2fd7ba04fb/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string80 = /7e2641906f4beeaf11dff6c4aefc9be37bae9a314ce2357dd88b804387ecd096/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string81 = /81CA3EC4\-026E\-4D37\-9889\-828186BBB8C0/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string82 = /820d4bccb36fefaa8b77fed456872ddd63a433fa5ce3dd024ccf3f9c93710c30/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string83 = /87d7db96fb7c8fd8668f69717d84c9cc36f3c2ae96a8ef2187fb4b3544fabf5d/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string84 = /9135fc8890e155d1a3dac0907b5081e171cbbfddb6e19e238741d719c951d2ef/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string85 = /93050aec30d7f0268e4fa3ac695a1131f838fe19a625bf574c322c1914b76c93/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string86 = /9aa8a85153861516996a7c38d282bce08be9fb8d1d5ea707173fc6d43c5c8e8a/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string87 = /9b8973d38cfee2c1e90385a1d25741dd4d9a72f426252719ac46bc8b89975618/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string88 = /a54e83a923cedcae9c948e438cc3213c49e2c207f3914fdb5254d213d62604eb/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string89 = /a58286cef52371c6103a194d90224cd693e69b544e06fa40784de35af6277512/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string90 = /ab5ec32d639fa8346bf81b3c610f87a14977c7f7151b869214f43904d96915ca/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string91 = /af75ab9765d7f9003aeffef2587615a1f57ed9b6f1bbe44830592b444da8f295/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string92 = /b2fbf30e0db9dd21a011d733f210f9c7944f4cdf3903c352946c3f88e760746d/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string93 = /b4c16d2e012d0c946e0826ab7e34acc035eca9d1a94a5fd30f394124296c962b/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string94 = /b5649a8ea3cc6477325e09e2248ef708d434ee3b2251eb8764bcfc15fb1de456/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string95 = /b884750041a05d7998e07110ba366d19af3c35157c95524b240707f81ce9572c/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string96 = /BA902FC8\-E936\-44AA\-9C88\-57D358BBB700/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string97 = /bca2f7b65962dc1ef67996d9c853158b9beb3c73755fda6c217dd2883b9ab29d/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string98 = /c3b6f554126e1bc5dee6dff6d0b8dcd7241abbccff9898be3224ff90912c6c4c/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string99 = /c4dc53f4912605a25c18357b0a0bf6dc059286ca901cb981abdf1a22d1649ddc/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string100 = /c7647cb1c2631105bb032dad94057bfa62970d70dfa48f8be0c1a4160ff7c56d/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string101 = /c99142c5e55fae055955332964c56d29aba10bec9764ab961aebabf6c3ee1462/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string102 = /ca32067f8f93d2cc0aa1ead819aa8db3e6803c1e535e377598548f41c34ccac4/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string103 = /ca5ae82e1e5269bc00b2539f84d0c5d258601741c905b7fe02ff6bd6e06089c1/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string104 = /cb36d409779d4a7b0285552c3bc41efc576b4a22ca5fea6f4c288e1e96f7f4eb/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string105 = /cbf8cb94407c028df22b4b16607adf543aa3087f079c4d7906bbb1d9081b7179/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string106 = /ccef810ad3e3d55975e4acaf210e75ee63fa5de1069c8c4ab1579765d541170b/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string107 = /cf194caf93ce5a46768876b5fee0f644f6878e0a4dea0e391bf4ea1689731cb5/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string108 = /code\.onedev\.io\/SoftEther\/VPN\.git/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string109 = /d075c00b275c76255d94d50dcff34b3e8238783c137551d3eeee8351eaaf2361/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string110 = /d68eab271b4e5ec8de105d2bf87d9b3bf6b1f56634bc2259573ea371883d31f0/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string111 = /d70cda7c8116dab7b29389db19375fcec3422cc05737f8f151803ad767eaac80/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string112 = /d7b7a7f5495c5fa5ab70827e041e6f48b2e3a13d26c83706369f8b83080a2e8f/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string113 = /dcd12874e909f6f973d17a9a9a4bb2bb5c0eb1dde3c840a01d9b8a2f89217e76/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string114 = /df5b10dce307f6a8cbec606b0eaaf11dff457a5cc46c1b16f62cd29d39e610a1/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string115 = /dfb21c50807a7fe098be6e333af0807a1b22f67abf42e036d06f06d594a01fbc/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string116 = /e0f22e76771f73fd1b8b91f8ed3c6d2ecc3f5bf1b8b72e8a0208ddc43bc83191/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string117 = /e16fca64d823fe922146ce8d9d908a4fff879dd5a89985f547661706579eb240/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string118 = /e1e0882b31d096b3d7c4dd7e433dec30e36d165610621f4e34a705b35fac5335/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string119 = /e4c962237d4b3e6e4af1be6082ef976c32b80d17b5c24079b9c59f0ba9775e7e/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string120 = /e5469979ac08d21bad44cd7696187e80d4ef78b60f473a954936de4cbc3d0381/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string121 = /f0d3f6d841b1d8e4478f25771fa6f58717fed13de6c28dec36bf497c7b035853/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string122 = /f139f24cb99599d9f666d925cf0371aff4eaf5fbf531634ee3a2740d5b646da3/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string123 = /f1b1b2b181d6148660067534534e7c85f49241068fca8b3c1f6099216b67fb39/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string124 = /f402294bb18473a6dc22baec0c86e635cd2bc0423cb10026b5cbf9d6efcc698d/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string125 = /f7fcde269f7db9393f6e548fa4c0507f7a76b8a9a44caf34a69f7901463be977/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string126 = /fc208016c808df328b5dfdecbb8b40883e1d10b3c064ea6a1126fcf3b8927531/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string127 = /gitlab\.com\/SoftEther\/VPN\.git/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string128 = /HKLM\\SOFTWARE\\SoftEther\sVPN\s/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string129 = /HKLM\\Vpn_Check_Admin_Key_/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string130 = /http\:\/\/get\-my\-ip\.ddns\.softether\-network\.net\/ddns\/getmyip\.ashx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string131 = /http\:\/\/get\-my\-ip\.ddns\.uxcom\.jp\/ddns\/getmyip\.ashx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string132 = /http\:\/\/get\-my\-ip\-v6\.ddns\.softether\-network\.net\/ddns\/getmyip\.ashx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string133 = /http\:\/\/get\-my\-ip\-v6\.ddns\.uxcom\.jp\/ddns\/getmyip\.ashx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string134 = /http\:\/\/senet\.aoi\.flets\-east\.jp\/ddns\/getmyip\.ashx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string135 = /http\:\/\/senet\.p\-ns\.flets\-west\.jp\/ddns\/getmyip\.ashx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string136 = /http\:\/\/senet\-flets\.v6\.softether\.co\.jp\/ddns\/getmyip\.ashx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string137 = /https\:\/\/.{0,1000}\.dev\.servers\.ddns\.softether\-network\.net\/ddns\/ddns\.aspx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string138 = /https\:\/\/.{0,1000}\.dev\.servers\-v6\.ddns\.softether\-network\.net\/ddns\/ddns\.aspx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string139 = /https\:\/\/senet\-flets\.v6\.softether\.co\.jp\/ddns\/ddns\.aspx/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string140 = /https\:\/\/www\.softether\-download\.com\// nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string141 = /service\ssoftether_server\s/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string142 = /SoftEtherVPN\/SoftEtherVPN_Stable\.git/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string143 = /sysrc\ssoftether_server_enable\=yes/ nocase ascii wide
        // Description: Cross-platform multi-protocol VPN software abused by attackers
        // Reference: https://github.com/SoftEtherVPN/SoftEtherVPN
        $string144 = /update\-check\.softether\-network\.net/ nocase ascii wide

    condition:
        any of them
}
