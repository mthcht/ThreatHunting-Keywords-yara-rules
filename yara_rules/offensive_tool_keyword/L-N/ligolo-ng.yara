rule ligolo_ng
{
    meta:
        description = "Detection patterns for the tool 'ligolo-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ligolo-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string1 = /\/agent\s\-connect\shttp.{0,1000}\s\-\-proxy/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string2 = /\/ligolo\-ng\.git/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string3 = /\/ligolo\-ng\/releases/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string4 = /\\agent\.exe\s\-\-connect\s/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string5 = /\\agent\.exe\"\s\-\-connect\s/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string6 = /00fe1c60b036ec30ac7334f710f0f923fdc5c702808cdda67c9d5a6fb2041ee8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string7 = /01825b6b38ccd13900a4b83d2fb63f5246c775d05c032dc2d57c84c5b9940839/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string8 = /02c6a29b238259a0246547ae5555099e9b64408fe28fec1402e1f31a9ab83e88/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string9 = /02f70aded03c76e395624ff19b9f2483b4cc88309d82ca2b5777daa3a5563887/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string10 = /0426de410fb8ce32eefd563d24f81f5227bbb5a283a729bfd6b36adc50aed7f3/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string11 = /04f2d08d79da097f7783031a57aa6685e5bdbe7589dcdbff724df1d9bad41d53/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string12 = /06adfb5d349e0f02863abefa92b0ab3e605375651ea355581b97b864a2248110/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string13 = /0748293c2020daf803a3a57f1939a98fd25b074eff46b73028550f431f91ed32/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string14 = /0756dc393b6d41fd03e69063d91342c43e60e4ce5fc63706bda46da0f8913657/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string15 = /083dbfe9fbd1a94c640aa2e80c0304ac49d337b15f6f148c2f91d2c21a23cbb6/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string16 = /0866f16193a1944b2208ac9d22d3f629113eb968adcb8872b2659ec749c6f31a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string17 = /09348db398b0f762f8bf72cc8fd76268833be266918c177c82bdb05e28c79c47/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string18 = /0954c8a613c18097f0086265db97e819d44346d52752c8d760a90e5bc6888f98/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string19 = /097a7a15058a4623f758a7667857145abe680a97c61255e2aa8f6086ee4fe365/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string20 = /0a65867b6b4cb21b8a6bbaf06b355a36283b30840e02706bfd740c9da9f4197b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string21 = /0aed5bc1f0d272aa57c3a1286499e49633de6f192cbec67f5f7b536d96fefe8e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string22 = /0c2bcf6e46488c60fbaf6ac42680e04d6b7dd461139acfd86b934cb6d43a7c33/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string23 = /0c7db3f692255998b52505a79ab8323887da451368d02a2e9aa115ae48bd579e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string24 = /0d756650eb56b7e3ffc5f27c01933fb3b4ada09b77b77959ea4178a0f46fc8c8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string25 = /0d8d349782ea9510389351185bac60105d17c181a9271f7ab99f6d2c886eda7e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string26 = /0df3b8f4bb74d6867ee75afc9c79f76e6ceb4d1ebc7b708cc7b137791d6d15d3/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string27 = /0f06194447698d2570c3ea97e506da0faf309a8e63b8e4e2b04bb99a1e3f0e6d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string28 = /0f699c5851b2727d8a1af5fd9c7507ac23e39bd072619866bd9e6774e6595efc/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string29 = /0fc989cd644f58ef166d409d2f987bce4fa1544ca0e357d40095ce75ed444a7a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string30 = /127449a2c9bac7f318aaf2ea709c7006875ddb4be79448f3f02db624e15a6540/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string31 = /127a7893890a5bbe661beaab8ecd27a565ef636c890cec15544480836f161a94/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string32 = /12987a2b5075539702057175b5355b545884e49cc5d836f84ec5ce8f2cd47635/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string33 = /12bb1ec9171a601039a806395bb84d225eb0ac7e1ec975b91061dda5894b2dd7/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string34 = /12e90d90d2c9c31ab613cfec98d6b7b982610ebbe460536ece39593a7eb16596/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string35 = /13d08385c57fa21b113a4c2afc60207313926a79fbca29ed9e9f675685cfb873/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string36 = /1587d5a67e91ff3f4b00b409066305ddad3796be41945de2a486b311b9425b97/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string37 = /158b4c36722770abd1f8732a19fd32a61d7892dc0fde6ab220adfacaff5628e8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string38 = /15a1788abea29f55f817e7b9e19fe006fbfac0d5b6ff038b638c4a51f4e08d47/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string39 = /15ac2ce4714d343601fd09ceb2182f887d094e7311135bddf50b7059c1ab4a9f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string40 = /1616ff243a9688f6a5e9bbc73f428ab61d2ab17c9b0c05e92cee43c0589b8315/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string41 = /16ab1f4deaf16ea10b420b7f644da50978aefc3a6fff18e569f713689dbb050e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string42 = /174026948da91b966d499e4e3cf3ae425588fbcf792a76c5c18072df00112311/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string43 = /198a5ea52dda1eeca520c018ef7b21a217ea3a5ab7a3f07327e5ba0f172fd33b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string44 = /1a1c3d4c9b4d634ef0f741a0fe610935f6c5c0cf2c0cfc2a4a6d8b3702731b1b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string45 = /1a9b73e2c74c9c5b48ad54e0aa0babe1241d117bc7a9c4cdf7977380da23e089/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string46 = /1ad1c6e6c95a5a5064706a0312e0668eda560fafd0ceea59eaf6441e3735a39d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string47 = /1ae96f5eef721bc51a89dae07a4635d29531b2e11ee497e17619f00b07acf1b2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string48 = /1af96d83e204abefa20c59e17e4a43ba2752360aadaecc0a8885537108f1aec3/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string49 = /1cf2330bd7746cf855dac61e732dd8105a5a62e97d918e88e8f9c3514ff2d783/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string50 = /1d10b68b19d7daf2ec05a7b9d2683b7e4afa81b442781c1884f67517d323c999/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string51 = /1d502988647b7e21c22e7300484d382f04132e3df644d93752457041a4aeb21a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string52 = /1d8c3c650deb96f67cc45bd76fc298c483cb961f04ce157bbda8e5f2cf3f12ff/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string53 = /1e64a9795e35454189e28fdf181ba87960381f3d547a883048d84a119c4b92e0/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string54 = /1f75919c77b307ea48ba3dacb257e8b9d13c25db0456bdf9597611971f584f3b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string55 = /203e97f6f0cdd98944724e4899fbcd84ef5a84c85e1035ee303aaeb76756b95c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string56 = /2084e9586af146731e47db82e3ca1e97b50c63440d4ddf865248dc4740758c61/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string57 = /2136caf310bb8cefaffbe9fc97ec18efc8fee99c071dbdae5e18840c71632ce7/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string58 = /223c6a71be1b15a6b28dbe13bcb8ed5ca46b71b0e1bc014edbac35e3d61dcfd1/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string59 = /22eb92e656efbf120016e4483ae92a7accfb20c307faf7b17debf52da27277ca/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string60 = /22fb8aa73c70f98115846b88d6dba267df70e65ed16fe26d0241b206864537f0/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string61 = /22fe06596a11d40b5607f1d7a51a5a6655aa33b63693e0499a0d8b03276e44f5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string62 = /23e1a48eba4387626c8cef3e9a8268a7e8ee36ad8e76bebfba79ce314dc4e90c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string63 = /24046f3805d3bc40d71b96fdacae5e02d2bc41a47cb56e178aa92bf6c373177c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string64 = /2438d7f90c0d3cef5082dc9072249c2965d6bbd5caf777cc00b09c18d29edcdb/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string65 = /24b25698a2b1e5035978642fdd0fb07dc44018e58723a4a674ff7e6c2bd3163e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string66 = /24b3c82f54df63a856f237eab7bb1f7d85cbe83bc9a9f2c77df1d6abbe03268c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string67 = /24bf6c85aacb6285b8f89f74b59ae1390c767bb9de880afdff3047117bc9d18d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string68 = /2672d3407c4e05697db342691363db2953fe732c6d87dab56888c401acc7e964/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string69 = /26a4bf1b21bc16bd38c859e0d6becb178106843a914f5657d649f9d68e594eb9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string70 = /27428e1d8aa5a20e6474049810d7615dd529c9671f331b9bf8f6c959ed36d7b5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string71 = /27758795eda198b3d41b490d11b0a33684b63aa2d33c716c65c2242d60b78838/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string72 = /27b23ebc1517a37b652dacbdc375db6220fa005bdfe4f7d522d6f1e277688541/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string73 = /2833afc31c227a193622b57b6a5e1093add63d853a276915081095f543d62099/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string74 = /2a7968aa8897afc8da0024530babe71fa7e6db8d31e5316a12c30e4221f198ef/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string75 = /2c2ce45452521b88663a2ecba9eb2fd7605b3a2d67924bb59e9f318a2a26c82d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string76 = /2c71826f310dd00b72e4838d3143745bc68d45e8d88f71c7c22caaabffbc4010/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string77 = /2c9fbc55ba53269120d7fb4fa0f7d5ba0e3ca8acc86385eeadb330ece4510090/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string78 = /2cf90c4ce3a4376653a8b7c236797ed5c3451134e05b299abd14629b8fab0a1b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string79 = /2d7764b3561efab3e82c6f40f444e7700d5357ee4cf46cdf3233e37849153880/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string80 = /2e7c7e2e3546caafc5ca9729bfc5ae561049e75f24ce1439198caba776996d66/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string81 = /2e84c88282d85d3b93ae2637b90e3f4388fc2f96092b7e7aaa8e66b288549930/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string82 = /2ee22d22298209b3f5114b4f64a067d1933477b6c5259e28cf8f8d387450cb7b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string83 = /2ef48f44bff3ba1d7d63959971a7b04f2294fb0e8926beab26692e5f2f361d44/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string84 = /304900fc65b3540b7ae14e9c8813311caea7b57d1ce54b7c519adefee9a60e9f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string85 = /30a4f702dd51a4c04de7f62966622a6a85a77c77f5587e880a2d46b8e93325e5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string86 = /30e7fd50bce6e345e3a83a1ead175bccb2b388b0b95bd11b36095a8928fb796c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string87 = /31bec1471840a741ead2128106a98746d4b346a7bfd737579dcc088d31b00eb5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string88 = /31dac83a82cc54324ac27d4754ed64a5ce454d8d85dfd8d2690da656ff7b304c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string89 = /325e02205522272bfa9d390ff16ef35620b45fa9422b851c13e0177c56dfdb1d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string90 = /335ff83fa33730df73dca7bb504898b78823c065a7437807fb9a2ff52d5b14e8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string91 = /350ddee8077a8a8df47d7a57b8d25afaa7915b4a7b79bcd683684723d0f8b669/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string92 = /352cbeb2cb8456e9462f30ce30e2110101446efda08aa6f36e150680908b638c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string93 = /355a9a09cf1e95bf38e89df4c267121c3592c873de0ee9912afaf2cc840e77ca/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string94 = /35962679b2963d0c6af600db73685b744495e6a65a24c3c9809e8ab2ef52225a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string95 = /36a8df8ded4e69fc68c172aef01afc33ab8576b130987c5708b8dc58f714c4d2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string96 = /36b81baa1376efd694fc671e7ad2791b223d31762dc2bb32d919addaf5862f02/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string97 = /36c3075114a8f3fe901eca2b4088929047e82a7d7e762b47fcacd7109eda0407/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string98 = /36c6235d0a635f47045fb9eb24715bee64d25024c3f33041deeb114efda6e99d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string99 = /36f88cb90ca8084fa93158aaee6b8879fb75ed8c3c12e946a32ffb7ef6023817/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string100 = /37ef8b7afc3687a48d331b98d1e4c350752ad943f58c9aa5a23d4fccb58dd574/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string101 = /380412e02376173ec8b908679c7f74053cc8199c9ed3138b8b54a6175ddb08d1/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string102 = /3809f2663ab0d7408d98b48c70b1d737d7b9d9b175ad66fb2d4cad8cc636b239/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string103 = /38782e6ee72ae26ccbdf20f4179ebeb94ed5c1e9a358dce59ac5e220336ab3c7/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string104 = /387938818fcc342d03c211123e30922e0d219262a66b988bbe54b6958edfb73b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string105 = /39a20042649a8a218ef4cb738fa9f4ab1d6396b35b741779a7e41204b828974b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string106 = /3bc2220dcc58819a4a959b434678da39a94f5b03b46779123a5c341f2699dc6c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string107 = /3be05874bbab1a8400a6f8ad7ff13f7496513d0eff1620de74b7192eff2327ae/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string108 = /3c00990e4f6c4e621ae80638b66ceb60e39ebe727d7f91d36e99a5aef53f6359/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string109 = /3c145dbeaaca5c563c4fe634cd41deeab29712834d4bbf324e0268aded1013c7/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string110 = /3d3f4263b35b7ef1bc8b9e9a70f9ef9b6b5625ee20bc5605d13607bcba64a5c2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string111 = /3d77766aee0c6991e73b44c34c3014b25e1c0730e89e593c53f4f846ca0bd40d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string112 = /40779b8832f29dc3cf31a047d08e4da5aeaddfc8893b86b8f3f4e34bbb9cec1a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string113 = /40834c0deedabba1254592d89b7b7a3af859f3d4e037226fc81eb771eb0a9406/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string114 = /40c04908fd5b240769a49825c02b50430948048234edf25d1b48905add12c275/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string115 = /40d3e3372bd58101f50a25902a71a41fd1605652fe051b3e90660563a9fbebd3/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string116 = /40e4a1e4db51c8aecc7f13b8b3329707d0e353607b83e86e776bd4bfc480516e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string117 = /40fc9bd6c327b0384488f7935bc7ce65c84b9d5076561605b7743be82840f3b5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string118 = /4265bff36f0564344447d7c71a1119354e408c3acddff3bdb27c61e7dac354ab/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string119 = /429ce1891bbe55f6b39e8c0b32ddeb392246f8b2186b32a348114965453a3f53/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string120 = /430291aab4a597081838f02b2ceabce6f5c8bd59334244c82229e4c648d28ac6/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string121 = /4586fbacf5d78e868b9b823f3109d05f73bc30cc111d1af34db3e0bb54655dc2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string122 = /47fa63cb5af6b062d101ab4a8d9885c089c3ab238fc5e9e11a26680f45e5250a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string123 = /485fc17f62c8fddffc7e65f7dac7675eb02912abc6930260caa3b3aa9613b3d0/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string124 = /48fdbb3b4880b7cfeac74fa40d699f0cee12ffa0d7d2ad1eed7af09ec341b24e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string125 = /4980fe8b5f9539b07e8f8ab36c13672558741048872fb2d983adca48c567e193/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string126 = /4a284165c3aab4ccc0a6e97353d7bac85b1fcd7160d020eca7b18cd1608ba1a4/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string127 = /4a738ce94499ea3c39ff65328e513db7df9db009d6df5422331f30a09b688e31/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string128 = /4b10c2daee126f80f9c19d018cbbd7d2f06c05f737a16c38e9aff1bfb951b2f4/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string129 = /4f0f61d1c0b3904b0a3409f8ff70af3b822b46e4c7f2fca0b642cc278b56209f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string130 = /4f92da7a73e1e1fbe833d6208e7e7b9ca8b62fc5865453e8bedf5ba3ffff2531/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string131 = /4ff3269f19b3cabf56ed566d1f43636587c6fd61facb013e69244babf3c9c2a8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string132 = /503e912598061959f6564c5be9aa4f4ad4ac2a6530f1d84387fcfb7915275285/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string133 = /50feb4f8f0d8ae6d64d2b65957a4a6d597c451a89da5970d0bf37d1ef67a8fbb/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string134 = /513c40085db62d92e26512d78a40e9f32466f45f563cde8cd6892f5b135e8aa0/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string135 = /51cd17b43ad9aa99c77827f7ce8ab9f35d78382479cba7b4e1f479e1e5b4bed1/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string136 = /51eb3cd6442c856ef7e5170818e5bcab3594d6b3473a380c9a1555ca1dc2eb87/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string137 = /525fe993592ba892d62bba7abc5c364dbcbb82123ca76fccbb8993751e32a748/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string138 = /5323c783db3710a6802c7398d387b027115a1fccc2b98888a820bd0f0b0ce605/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string139 = /537afccaa5bf9ab3024691cea87acaf87f457798388856ab41bde9e30515c300/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string140 = /54138c7dfb078ce768fe9893ea069bbedbf249a10add1e3a772aaa14497ac863/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string141 = /54398ce81884b96d375b383c19b990208a38ca7a4d0fd05716a33c18713f4c29/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string142 = /55004532300a4eac4abf5f02f8c20e6c0071ffe1ce065da805f7f45f3e154a72/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string143 = /5523069e10c357b8a5737e287ae18fc0d39c6870a724f40e4a49ef9a948c74e0/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string144 = /5548fb14ad8d39bd75f82540c19e571edcc8dabb3ba6b4b46f488bfad3035e07/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string145 = /5576bc01df05427e60683abf6c5f01b6a3ec4fbeee43ae68bb1fb20ba14b49a1/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string146 = /56c40fda72d7c0c202d57c7c69690d348ba9bc1a1f133cc6d39cf564d560cb1d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string147 = /57a36d59b199ee6176b1bdf951cac5e4dcd3895a0e5307706b12b527c0cce9b3/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string148 = /591034aa486803adc5b5d4df97d915db89616810ceac4569761e30190f8615ac/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string149 = /599b1b33ce473c83abfbef38d7fbc7108bd694004047832559ad3d9c83857aba/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string150 = /5b05501598f6428054255538a2fedd435e439408e77f8b426c31b83597460565/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string151 = /5b5ec9cb61bbc187ad3ffdfaa6d782525d9574c9b3fcd5e694f0d25d60531074/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string152 = /5c66b553237114b4d5f347969bc2321bdf916fda972e947dd7590640bc9f4ed5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string153 = /5d593ef77ff46bf12da1f807f85c0971ffb44916c275a12829b5fcb4b95dfe05/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string154 = /5dc10484e657c478f1740c45b19bb1e46a0edee7c4c89da9977359cce0a4958f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string155 = /5e1350993991046a366a985916360cf8024f2ecbc6bf595da691226e546b14fd/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string156 = /5f8801faa0e5801368ca51f92bf4483c663348465d00e300e0323c081833c8a3/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string157 = /5ff6041ece711cce493b1f305eda3b9b619fee0df9061d6e324de131e7b2732b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string158 = /6089b1431d6107150c713a5d83c664be739b2b2f179fab3fa51d1280c4124adc/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string159 = /614cf381758fcd853c8aa47a2e3910979fde5751d7d0239149f0bcb75c45c4d6/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string160 = /61e6d96902e5eae3155c70f26b7cd5cf544ab5907958a451d34c8ef08688c71a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string161 = /621ee90fbd4723db93d31f385fd3ecac944076a161845d433755faff0d3069a8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string162 = /625ff12afe53772a22004e384bc21481dbfbc0b4e25dce987e814304e586338b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string163 = /63cfc7750ccf7f7ad82a20890b6957069e0471d976a0a3a960ebef69b6641234/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string164 = /63e119d9a3c93d0751e545753aa05c59ed767d3d0f87ae6b9a4309573899f117/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string165 = /65d963e0cd748cc7599afd69a0f961742b17cb46d67414ce8e9cccc087b59342/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string166 = /663a4660da761fa144f2b5a591f84a081d29f62d881d9d24d8f5e0e8e5341a84/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string167 = /6743328a2adebc279e702b4fbfc978b8689dbe9313a157b3cbffafd3a77b610e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string168 = /68e3b0998d4950b98379f5c42a3d1e317af5c3ff22878e9b569a563cf28d78e5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string169 = /69ff7f809ee0a683102bc50c9c7dc6b619945c0d5c774c577b52879f65ae9dc9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string170 = /6a7a023923c747c9a2b6c1664da1b04a45c0b978141d189794110ae3768f231f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string171 = /6b2f186837bba117f38583e6f176c56cb59e0d1bff76f5b8ad538977f00b49d1/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string172 = /6b7819ab7d2400b9da53cc075e67d32d06a29c647afd19ba21c2197ee11f5182/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string173 = /6baa01602cddc4d7a7d85626ab56c3a5e5f4abafef152af6304e2caa62d7ff9b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string174 = /6c07e0eb6cf4e7ed13bc4573817151451342c822ea9d52becb1865e2a761cb57/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string175 = /6c152888df8ae98171b78aeea0a6d9935b371eaded61a067b82c1cec8edc0844/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string176 = /6c615c17a6bd1fc0ce0f1add0b254e60fc162e44d94afc77ac91c2d3e9bb65be/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string177 = /6e0737510e4601410e0312c6d1f8d3d98c79536952abc4fab0df75f490ec7f78/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string178 = /6f1799422f0ccd2417e550b20fec04fcc7f1d9ec78aaa1415456b3068f673f6b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string179 = /722f4e5abe79cbd2fa8cc52459494082fdbdcffbd629d7e04907b4c1c8575ca9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string180 = /723d6f2d441c021b360b85f7f78b85290693cf6abf1376ae93cdac06832edeb2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string181 = /73aecc573cd5fa9b83875ab373a7ea718c02c2c2efdb7fcc8d84bda504d28ed9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string182 = /745a1708e179bd41883666ac0c5c35c615f1dd2a730ff0c1761beb5fc7ed7248/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string183 = /7596c0126181b25c5c68fa91c28bc36d4054dfd94ec424d5209363496482511e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string184 = /75b1849a5f5a0c0ace9aee3df84be732f5145421c2ad91cf77933ceb0c5ef069/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string185 = /7926cbd1800a74416a6c36bdb022f80a6e217a3952099b5e929f9a183416bf49/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string186 = /7992bdccdeafe04123c097c807381ea987d778b6c8d527937f3eb9146ae39a54/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string187 = /79f5bb07a32da20893b7d1755cee8b5f8f637d5712eac1788b796eda90e75de2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string188 = /7ad1f7ec564a2343ada204cfc7f8d903c7c7d623923bc5256551cc4d133d724f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string189 = /7b5b75b4087cb25515ce661dc7ad5be184faf4f3a03173f895e6f275ad18380e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string190 = /7b81753062ad8adcc3012d1e1f78c6cbb5d8937e61a51f09a9d649bd153b0d03/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string191 = /7c81d08540dd014938278a2f8edf99b75dfb677804d8806a67c1fdb70c49efd6/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string192 = /7d98c9c00f9813e45f807b3d5779c10e38b4191ad8e7c25669c0c7a3e3ce3cda/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string193 = /7e79f9041f4009d963ab05ffee97702646026b16bed9694e059b813c261b973c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string194 = /81a130c4d44dacad8a175fef8eeecd9561e938f8cb5de366795a9213b76fe1c7/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string195 = /826b9353f66c3b17151b57e87e656314b6ec0397dcfb5cb2f61faa6cf92c7c91/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string196 = /83aa5d2000790bd20d5c57f338668fb576e76149c0683b067a62d151bc2838dd/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string197 = /843053c1c1b36afc067f792748061dd1513252038e2dbe71dddc618bf9c11394/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string198 = /847d58dd3d25b7bab471a9105a7e7eef60cafa788e4942f37e87ccf4c740da5f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string199 = /8492e696c691cd0893990f2496f827632345c6c278f4503455e996ff30a8f185/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string200 = /84bd7dfacba7564afcbbbac2d2c63f9704769ef3b3bbca2259d3ab433b81dc62/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string201 = /85b041052e2b8aba7219fedcf3e54d9df17bb97185862df67b42c76a60d3ba89/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string202 = /863ff084e43b0829de8870f7bfdbc151bb486e491bde6d644ef82acf61709e0e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string203 = /864ffadb188961088d28a0b5c5965f88ed9d07ec8f4c2301bd768d2c0cbcfde5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string204 = /8719279d2e1abc87d952b144cca5724b9e513958ddacd679624cef890618880e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string205 = /8742b933c06da3e2de7f8945520870da234a5744bddd18c5339ff4b1faf0ad57/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string206 = /87e26c35fb03226e9a2252b65bf017f9e1921aafadc28de78ea583eb5730ea7e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string207 = /881a10b5415e1e8c83986a81ae9a126c361b21964e8db7b93149d236191b29a0/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string208 = /8838860eb9971c0490c4fa221b8774b95eaedd0f39ce12a94d4035eaab7a4514/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string209 = /88689c44114bf5819480752db5e955f0e74a2141d3f4b59f7030203eb2fb458d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string210 = /895b297899e043df918c8b93301014d48fc1d9ddf926174ea1ad5cf05cc7c79a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string211 = /89cb2fcaf93e959f54a336545ba2935749e33c624c0bd08a8ebfff72aea8d627/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string212 = /89ec75e91e04d7e807868b19dbf8adfe109d62762b4c2afc0e4ee6fd37ef7df7/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string213 = /8ae9eef729fd1a1c02406804d5c54d7dcd14507b77110ed543360fdb4f5b2f6d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string214 = /8cda5ed686c75c07bd1e2bc6bd173c3ed48c1dc52dbde4c596d571ad1f1a92ba/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string215 = /8e92ea80b86a38b2f0de7052da3a75175710f613dfb1195721a6c1b3eb53f8cc/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string216 = /8ef7679f55cb6735f37c83c4e5b0dd8d2143c2d279d481bfd4d47bd5be40fb98/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string217 = /8f08c9ab02e3c180eef98a8e28c2f9be584d56dea5fa72dcdf739c5753841022/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string218 = /8f45cb2ad194897123fc4cfac863bc1cb746a35e4f339261b88351d136289181/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string219 = /8f9c15a3849965a7739d98d4769d1a3c2a5943265f6a189ab74ea077620f9cbc/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string220 = /911db175f6d08bcc3c3f26bd5ea264434bb612533b8e7beceef307d35adf0f10/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string221 = /91dc86c0d4f008fc33306dd379f8db8062364478e08efcb807025303c85b6a59/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string222 = /9283d98179addb3f66170f7ac17111f1c91015b421f3e42416cd3b94894ca6ca/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string223 = /94eada8ec8949a866792d385ca5f5b23e314c310e67035f576604d9ef9bf9a96/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string224 = /950ba7173a1c869400d8b9099a42ef76c13546da5321f69da77819899b6e1d23/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string225 = /95aa09723c700a9e1bb225c70c26ac6f63169089ab7ae3ecdbb9b67fb23740dd/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string226 = /973d217af2a0f2b65c7000cffa1fea57cb816d97bb41775201342138029f132d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string227 = /980b1116ad7c83280e58fa50c2fc66c4d596a04b64be88b19faac781416aa9a3/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string228 = /982e0bbb1c1ee2c49d3be4ad0a076a402d8c07a9712bbf2244c39d5550b37587/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string229 = /98900e81fda3f034d4b54e347f69f78be803fbc76df09fc75ba56329bb21c03c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string230 = /98f7e2c5724e79af170510f1f694fb61181ea985d4964286ca3865e2e0de690d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string231 = /990d5ff1bf1055bd4796de41e1fc6a31dbe60d11e15e64f1eb46cde01fbb4c68/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string232 = /99a342f4ec5b86e7d657a933f5f56aeccd9f540193501b3fc6d6c8cac8c4bde4/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string233 = /99eb7ac696d8a296728e64853eed90941ca96c597e2c55e4fe7eac06b7aac152/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string234 = /9bd65e7bdb3f403886a253cc9944ce4f460812ba9534ad4846b97fa13f6a81ee/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string235 = /9c86335386ac653a324d51c1dcb3d43704a00da106833ecad21e5ffad4e8635b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string236 = /9c86afa8a40314b53a51281256047f5ecebbf396a7df0dc15fc54687016d88a4/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string237 = /9d3cce7420303a3eb892b991506ac45e00118f231a41a539b0425b41ec9188aa/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string238 = /9d778c3e1c0e383e85dba64c186e25d953b27fedf500f1e974f66f329bb98faf/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string239 = /9f6b1665f8bb3a07f8b63b31944376f3e92254dde22cfc4136e3be206b54cabe/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string240 = /9fdebdd052d328f15c841b9616ab0a2344a02e0a2fad25f717a73bf6490018ce/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string241 = /a29c6f59fa8fc621166577447b14cbb8b4c0c4e29eb02427d359beade9148033/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string242 = /a34169885cc3ce7676197b63d907f44dbd7312e33498f7c6701e3d81af69154a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string243 = /a3a0bb972adf5e3a1bcd6684e0569ce704cd46a82570a7fbeb0c8ae8c6dfd65f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string244 = /a4b26a3d01e61601dbc2a82f6301e122847e57be910cf80d77ba83c1ed290b6d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string245 = /a550b029c646ac0752424ac16545bf084de1052b349ce5f47e2c24ce1227ff16/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string246 = /a622eda2b4d3ea644a4563610e594e8e192d79ab2a135c6a4fd2e3f4a707f1b5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string247 = /a744ea58259da195e1ba7b7af5215656622649f2ddab02e66e9794b7770efaf4/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string248 = /a8107d674c8391e70cf7687976f9973157bcd2458cfb597a22e051c8f62f6f16/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string249 = /a8326d0a60d9ea4574fe34d5d65d220b85bfd294ebb8c7228c17c75df71182e9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string250 = /aafc409ee997c45ec84a4c5db029046b1b2a5dc88d6d3f720fcce26085378e74/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string251 = /abccd127ce9c264980e3f8e8b040586a33dfe2c0e7d3e95bd79f383c09900cf9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string252 = /ad23cc7c081e18f568ba1aef36bf1002d296bee1cb3ccec0958f328cf97dbe27/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string253 = /ad32bf0a043b3ec5c05f0a10ad724113bffa7a2871bac8defe8538322a2129f9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string254 = /ad32cb154c001fea9cedc23a2773ab62bc4d43491aea1060454713e396af5582/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string255 = /ae8dc27ab20f07935522d714f2015e0f978ff982ed2e6f1441ca14d2bf286c92/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string256 = /af719967446404b4dde33dd813806650b52c51e89d4752995d507b5ba1d1b649/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string257 = /b054a5cc8d12e9fedf59d13d0a087f64f598ce4486d35c888b40a2c3d7adf9c5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string258 = /b0740ed4a5a0d32d2d4081fc2875b6006c8920794463f36e467ac00bcb294d33/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string259 = /b10dd21ee337c753a9056e9ac2c0b5d6912a5a39e7ef1ee618a91297286e4d39/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string260 = /b138168e6c3df7f29121c84965648fea150456bc7f532cac39ec180d11aba33f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string261 = /b241d58192f46cf9b508518c1a31062b50731226100391b0dfa21b929c1a1f16/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string262 = /b29c1de4f6292cd455141ceec781f9b83461996486aea93a11f7804c6af5477b/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string263 = /b64c3a9b9927835384ce5106d7b3c9ade747243c5804159bfa5a64877c0a6c56/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string264 = /b6b9a733b2f7b86f8ae6a40ce230acb474f018c98e78da897a1ed631b653583c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string265 = /b6e84d3a61b5740043470953cd2029da16edf15e7eafd372d49748c2b931ba87/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string266 = /b72190a931400b03dc744f734d29162310c694f7bb85c9a78fb72589301dceae/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string267 = /b7604b1463e8ea6d3829d8b6fd147911877b925e920ae530622283d4f7cefed9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string268 = /b81fdf0e50bab32722ec97ff2193bbdbc086633104ea03cb00d3d32419f513ae/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string269 = /b847015c30b9a6cda3b856cc82ae840b50ca407a71db9d5a9785ef8073ded517/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string270 = /b9fcab4af77e110405b886ebf88159fc07f5da5f69d5d872867db2ee0809acb9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string271 = /bafb49c76d6541518e9f22b688d52ca60f4b8c4bf692c35652e8642429c62a7f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string272 = /bb63353c43f1a3ff8161674e4ffaf3835b1adbcbe6cba46b4aa7b06020f05233/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string273 = /bb8ca66193a7f85a5e87467806865b8dc7656db2eb5e3fd86576d4559bf9c737/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string274 = /bc878fdcd73cf4ee6dd19e0af9d85cae49a96862da17936f079c240e362f2787/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string275 = /bd1d18a030c57cd3c5827be08135daaa3bd79a83150928ef6349d07cd12f2b3e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string276 = /bddfbb42571d9ec3398d559fb93330e60a84cfaf737a00545767a384917a01df/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string277 = /c15919a683d0e4d1d71792876be6f9a7a03651e60a6a1db3ce1b8573251301aa/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string278 = /c1f50e0f88bd6dbb961180b7c9845ba431112e894c22554a581364e326ddc94c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string279 = /c36141203951c47b30ecf138ab62132a35c5d50451b862333e64602020ae40b5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string280 = /c3d5848ea1ce007268f965e577fcdbbf343921d0d75c52b981499ef97a6e54e5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string281 = /c43b0658e94f065828af720b96f2d5f130d3929c7b37867897dc2512375559ad/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string282 = /c51687517b8113afd3b26a2db8329d76ba8232069480c6fd49e255dd4ebe30c6/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string283 = /c5cc643b66c16b592ce71d7c985942c71494a8ee640940846d3d0578c932ad0e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string284 = /c6a8607653837d746af95e31b26eb9a5de03cd396270cf5733ba6468a4027cfd/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string285 = /c711f24519988ac03d68431f8db8190045a81e1068fe074666337cb32c7008f6/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string286 = /c804c43c43da61b4430b75946cff6c92443104eaaf8a7b31c6ec885159cd6ff7/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string287 = /c942e9aa3e16c4cad9415815f8e3faea0056d3bef8f9eca6373d605c84542f23/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string288 = /ca06ccf5e04e0ca3abd24fd5d8716a5fba124fd332abf89b8832e9e8b879ea0c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string289 = /caa9bf0d9c73fdc84aeed8abb19e9c81ad176abe83ae03d5b75daecd2c7925d5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string290 = /cb492d017e08e8eaed726559fe3ce8b499ec838392b9e669c6d781b50ee8e7a9/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string291 = /cbf0c66fd84a1f7f1adf764e887a1249afab4d475f652af4e534149ad97d1cce/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string292 = /cc353aaa4dfe442dbee666feab014fb3804ed943711d41bef4c4ab13d2625a46/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string293 = /ccb76b3f79b0450fa184f0397af54e3fcf485a796ed65100ad86aca81222582a/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string294 = /cd1c194264bf41748733be39fdcaa8ac2166f1121919a3b2eae1f03d873773a1/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string295 = /cd1ddc6d2dd63df1769aa54a0febd2c11218f54350d8284c10e5fd2d396a5d7c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string296 = /d03ed31e7d6b56b88203655622b4455767b43389fcee203370c6c292f7d37d7f/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string297 = /d10b6cff8410fa9d9a9d9253c19fe6968fa5ca8f0de3b496648368e07b468a20/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string298 = /d28c06d99ec09ac090e9b16340daff7765f1257eea94383aa67ad1f9bf0a928c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string299 = /d386714d1924af89b940a7f6a9a436bf07938db1e83e686e9f20bd4275660e2d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string300 = /d44e7580049c7a6681402f1824d64a4bece941456bc3f1ee22fe5325b9644fb2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string301 = /d547b2cb061f4bb9110e3fb3417ce310ca8abc47f71c9dfb5fa6c1c17373b9ef/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string302 = /d5832804b0ca494327375e299c908a2d12b39053fa3cd1273f1899125e467557/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string303 = /d60cd24ca6f3a3d684dbaa018525676e0b9829ed3c10a04c4fbd728747c38b75/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string304 = /dafa76f08d48da880f27b5a3c65a9e88b45f1ec7a6790759595cf9c3745c1e48/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string305 = /db316e36b24cc4e62eacabee4b9f4704fea5880a9e31508796b3b48c0a9911ca/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string306 = /db57df98645168a3896d882401bf1730ab0d5fe6821434503d3630d68c887893/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string307 = /dd8f333bb1fe5d749e7cad5a0629089ba540367cb018a1eeef5ff1f11f0df62d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string308 = /ddda511b0021b986442e74225967da027387842aeb9b88cd2ed51cfea1ff0758/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string309 = /de4efb508d6f89e6d638f4def3b014b2d6c5703baa5026e03990b7bccb0beab4/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string310 = /dec2d084da34a9d29f17ccbd9b7a3820e3c7e9bd903049054f3f115f33cf5f5e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string311 = /deef29cfacbf4ede0ee55bdf0a4d9c0aa8a53d33245849e7699c12148bd06865/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string312 = /df31292f5844d7a8c8ea8c37704d23b28b8598449cda50b6cae9e85614277977/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string313 = /df64eaddeb2763b35b10a754df7492a2d305fdd8873d847e271e48c6ede05783/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string314 = /dfbff267e7b977012d3425c75caf46618b734284b26e9aab45cd5234e5f27240/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string315 = /dfd9cfda010ae5c691fb4e5beb2d4dc409674852a0181c4d8c0a8ed5675ee226/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string316 = /e0477338261831c6830884650d12f079a5a473547f5c76f70ecc2518aae62901/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string317 = /e0deeac091f3f0ed861e2c11d65fdb8e064bee75fd6867ef40b266e8f5c12f86/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string318 = /e15a5f2c86a2ab9c3276c3344960b6ee9c122645b0dd634c78d0617a47d6e0d8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string319 = /e1f73610acb162bda5e6e46fdfbcb52c9259558566a659d979b8f794acc624a5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string320 = /e2a30fed2c42d6b7e9098b8d7dda2cecab3c404b4aaff289d58dea32003c31e6/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string321 = /e331b3ba5acf93a468035ddc6d2591c5291574d64a509b4d511218c3bfa00f12/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string322 = /e3dd6fc036a50de83adba7789cd49d29da75622b4c0f84e0fad8ad97f8880446/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string323 = /e3e89eb47f5d2fec9f3fb1b32e0100d95d4a28d33f85966c217d5a859d4cab94/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string324 = /e3f63a8456b106e6e8c4801f2c061b1c8d2a205dc3c161e27ead03abbd960300/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string325 = /e4865da7718ce53f800a8a5990b5e3dfccb1350c9ec3831b3fc8c785d7c1bb2e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string326 = /e4c4d0282728171ce3f6cd35a92e8cb1ecd95635331b146105f5c81a25ac9c0c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string327 = /e5a25276797532ee1ab3c07ec17baddb9b7ad661890dfe2f9b91aa4db1eb2781/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string328 = /e6a224c7e04876dd864113178ed66d949cd74145bf813e440f9dc1d5ca7b595e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string329 = /e6d5c1e969b24be2c277ab70bb74169c45338967acb114a80bd2b78dfbdd2c31/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string330 = /e734ae00fba8f7857b092bb723980990dc905c521d8f4500f74a202634190bc2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string331 = /e771b4d016aa48c035fe6635758dcb84423b591684e1e952075b5eb998c91c1e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string332 = /e7ccfa126c99f4c6836b28455b1dae4b5a85202d8212f340ef3f3d1785e47387/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string333 = /e804b4ea28a60c2491bf78265637e7759df5c2abcda02623f3b534a908064801/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string334 = /e99696eaf1aef7f15ad9a71b917dfcc3bc9288c52808df07ac8f69a93f15aa9c/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string335 = /ebbfc954a86165453676f0671b5b4d24d58425c65245511ca04dbcd799934e77/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string336 = /ed59f3c5302dd8054c6f95575b26e7bb6365eb2d167ba97f6d8ee3bc5638dd57/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string337 = /ee09435faed339e34600ff9b157cbcedec2fdedcf6e20b058acd162eb720da1d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string338 = /ee229f4fa581d63bf7bdf8688a0b6386e3b01bb107165fd30df7c573897a094e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string339 = /f09d817e9523c32b31b29f2b6de48358e14b767d3f27709186f8629f35c991d2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string340 = /f15fa262d8f920942732454e30ba9d97487bfa6249e9ac561be57d567580f63d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string341 = /f1a6e3b13ff54c97ac5b84805277fd033f45ad2419b7f4322bd30adf72179743/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string342 = /f4e47eb7ffcf1a611807ade6cfb0ed331470a311c61b660cc5df5dfa2a254e35/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string343 = /f53acee57614581bb56dbb7af4a1de03128bbc7068bd312a5d7015eeeb48e263/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string344 = /f55a88457981f18729ec39762c4118802327b8cb1230d29bc4ecf31eaf1af9b1/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string345 = /f60e242e57d4caa8a918f9809f9a8ded3ad0f05d35be96e4ec1ad366dec0a393/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string346 = /f63567b66d159c784dd72daab73acf100c3025481b22260980a87d5efdc5a6eb/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string347 = /f63b78ec533b0b101033c9b5268933e0d788720388b136ce10ce83c9ee02fcf4/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string348 = /f80c3254650bae8f5efcc27f8b51d1b07d526dbd29291a8e5fdcef25ed0d0292/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string349 = /fa180238fde76bf5bab9300dadbf245b8c4d51deb46bba8d6b8f2a5fd1e99bb2/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string350 = /fb0eea49ed916aaa5428e80e86aa1136486e00f82637e099aa30469a434949f8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string351 = /fb19ad10ef4970540e0715a263a97025dc4b3e86cf94082ab4e8224a22952ac1/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string352 = /fc03035a9a7e7147f4a61fba442fcbbdc1a56e90880b731aa7c16909381296e0/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string353 = /fc1c5daf562d06aed9ffd945fb2766c5cf81318c685357444739926b47bcab1e/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string354 = /fd3bc4e3109f3d449cd27068c2b2600b852dbd2e35a67819d6a811b51027650d/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string355 = /fd5944e10bd3a9c8bbb73615c6b5c730e0d0b9bd9fcaee9a1b5d40d8a95078b8/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string356 = /ffe25c6a7a14c2f734af099af620d92bb87e0e6f6eb2f2d035c053232f7173a5/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string357 = /ip\slink\sset\sligolo\sup/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string358 = /ip\sroute\sadd\s.{0,1000}\sdev\sligolo/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string359 = /ip\stuntap\sadd\suser\s.{0,1000}\smode\stun\sligolo/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string360 = /ligolo\-ng_agent/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string361 = /ligolo\-ng_proxy/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string362 = /ligolo\-ng\-master/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string363 = /Made\sin\sFrance.{0,1000}by\s\@Nicocha30\!/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string364 = /nicocha30\/ligolo\-ng/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string365 = /nicocha30\/ligolo\-ng/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string366 = /Password\:\ssocksPass/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string367 = /windows\sgo\sbuild\s\-o\sproxy\.exe\scmd\/proxy\/main\.go/ nocase ascii wide

    condition:
        any of them
}
