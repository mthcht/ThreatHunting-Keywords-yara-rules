rule SharpSploit
{
    meta:
        description = "Detection patterns for the tool 'SharpSploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string1 = /\sstring\sDCSync\(/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string2 = /\.Credentials\.Mimikatz\./ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string3 = /\.Credentials\.Tokens\.BypassUAC/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string4 = /\.DCSync\(System\.String/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string5 = /\.Enumeration\.Domain\.Credential/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string6 = /\.Enumeration\.Domain\.SPNTicket/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string7 = /\.Enumeration\.Keylogger/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string8 = /\.Enumeration\.Keylogger\./ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string9 = /\.Enumeration\.Network\.PortScanResult/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string10 = /\.Enumeration\.Registry\.GetRegistryKey\(/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string11 = /\.Enumeration\.Registry\.SetRegistryKey\(/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string12 = /\.Execution\.Injection\.Exe/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string13 = /\.LateralMovement\.PowerShellRemoting/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string14 = /\.LateralMovement\.SCM\./ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string15 = /\.LateralMovement\.WMI\.WMIExecute\(/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string16 = /\.PrivilegeEscalation\.Exchange/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string17 = /\/powerkatz\.dll/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string18 = /\/powerkatz_x64\.dll/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string19 = /\/powerkatz_x86\.dll/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string20 = /\/SharpSploit\.git/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string21 = /\[\!\]\sCannot\senumerate\sdomain\./ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string22 = /\[\!\]\sIt\swas\snot\spossible\sto\sretrieve\sGPO\sPolicies/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string23 = /\\powerkatz\.dll/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string24 = /\\powerkatz_x64\.dll/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string25 = /\\powerkatz_x86\.dll/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string26 = /\\PowerView\.ps1/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string27 = /\\SharpSploit\.csproj/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string28 = /\\SharpSploit\.xml/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string29 = /\\SharpSploit\-master/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string30 = /\>SharpSploit\</ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string31 = /0d1448c1bc3c43a7a989e251079fcd0bea32cb8864b4b00cb8c17310464fd06d/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string32 = /0e26255b8db0b2e2792225febc5d3adeebc02edff523e90156c76b5baf7ee9b3/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string33 = /1bc8fca2c5b410f9c0bbfff18af3dc6295f2a8b8d7c2ba953e282b6a0bc6214c/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string34 = /1bff5a9cb5275afd7b7d4bf2d3087f1b3bf94864c4decf73f1c82922ad646d2f/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string35 = /23ae98fd603067f7325d89af5ed67ccee713397c2fed01ac736711a1b32e28d4/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string36 = /2c9ffb6711e510c8087c1095324e7ceef0187de6526b13aff5ab1e775f5ed676/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string37 = /2e321800803ff287f2c44203c718fa4a7a97dda864f1c2761e7720a57b18bd97/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string38 = /3622f69f847b1fd331363a847f626b9931363c81946b6d6e7441dc0959b4d971/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string39 = /3ee6cff71aef9e5d12e628c94a0c30e37b283f424aa487cf37248690d88c8966/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string40 = /409284796af4c4aa27849cbd51e721620fe0eaa7e8482207905ac4d79bce680b/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string41 = /4d31e1fd50918c09718d0657fb2c158a647b38ae833a231f52c717077d34d3cb/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string42 = /52040049\-D7FC\-4C72\-B6AE\-BD2C7AB27DEE/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string43 = /52083b583a80716b034b5ea9c98d0070091d63c2a13771afa42268cec2de7b1d/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string44 = /5d43bbdef3c107cf95891b56c5b40febf853f0aca57991492a4025032a8fa050/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string45 = /61e2497d69dac4b2bd43cb7f8427a81c52eb4f75e0b75b0550b136f3beff877a/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string46 = /6fd0b65efe28fce4c186c04c467198ed5072bdcfeb90e939b06563253c4eab44/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string47 = /7760248F\-9247\-4206\-BE42\-A6952AA46DA2/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string48 = /7760248F\-9247\-4206\-BE42\-A6952AA46DA2/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string49 = /7c8dd8b38777d6701ea54b98193216b808e2c7cb560a7cf1c07ef9e6b134dc9e/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string50 = /7cb004e20f6509f08f6e7b33778f973378c8a8e3c8cc4530cacf1f02fee3c29a/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string51 = /8694c7e87215c274f09116eb2f13cd23cf847abc46a25977088873b0d353c368/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string52 = /8f1c38bd7991da18509ef47cf01ebb1f1527acce08a9a0b25f46f70486bd5132/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string53 = /9a1f72ea60bdc475d434f1582a564e0afaa6b68fed8318d2e955d931135818f0/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string54 = /a06482e7f00958c2c66cf33a59818551f697bd7f3a601fa227e97d75a5a1c142/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string55 = /a441bc5046ec91f60d5a185edbee6a17e309c87f3268bb9c45bb9c83bb28ec23/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string56 = /b22e1828fa279346364b3915e2182b42141a093fe053c43c4ae024061156a401/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string57 = /b38dd36a7b348f6350623b1156c9f8805f323dbb9d1dad4b599b6712b8962e82/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string58 = /bb205ccc783d22b06eac7ab9e5f2f14d793bf9b4ed6fe413f888463092ccf79a/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string59 = /ca26faa4eec38d70b7237a0d1da33577295731d34c9aefa08ecdb2e8000cb4af/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string60 = /cobbr\/SharpSploit/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string61 = /dcbc47feceabeaecb5941fd36b3ca000a18ebb5431cb0d415c44e1235140dc2c/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string62 = /DEV\-COBBR\\\\TestAdmin/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string63 = /e1641d2918f41349e233feffd77b4f5088e4bc250d30a7be67693f3a09025088/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string64 = /Enumeration\.Net\.GetNetLocalGroupMembers\(/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string65 = /f58d086ed47166b22d02ac004380311058c66aac51551a10b55d421578494f32/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string66 = /f9bfe85b5bad130a6e0d3aaed75193779e150e88613fa1617470cf29d11a05b1/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string67 = /GetDomainSPNTickets\(/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string68 = /Invoke\-DCOM\.ps1/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string69 = /Invoke\-TokenDuplication\.ps1/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string70 = /Kerberoast\(/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string71 = /Keylogger\sException\s\-\s/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string72 = /PassTheHash\(/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string73 = /powershell_reflective_mimikatz/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string74 = /SharpSploit\sService/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string75 = /SharpSploit/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string76 = /SharpSploit\.Enumeration\./ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string77 = /SharpSploit\.Exe/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string78 = /SharpSploit\.Execution\./ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string79 = /SharpSploit\.Persistence\./ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string80 = /SharpSploitService\.exe/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string81 = /SharpSploitSvc/ nocase ascii wide
        // Description: SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string82 = /Starting\skeylogger\sfor\s/ nocase ascii wide

    condition:
        any of them
}
