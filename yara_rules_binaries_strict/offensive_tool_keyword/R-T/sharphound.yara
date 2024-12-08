rule sharphound
{
    meta:
        description = "Detection patterns for the tool 'sharphound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sharphound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string1 = /\s\-c\sall\s\-d\s.{0,100}\s\-\-domaincontroller\s/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string2 = " --collectallproperties" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string3 = /\s\-\-CollectionMethod\sAll\s.{0,100}ldap/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string4 = /\s\-\-CollectionMethod\sAll\s.{0,100}\-\-ZipFileName\s.{0,100}\.zip/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string5 = " --collectionmethods ACL" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string6 = " --collectionmethods ComputerOnly" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string7 = " --collectionmethods Container" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string8 = " --collectionmethods DCOM" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string9 = " --collectionmethods DCOnly" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string10 = " --collectionmethods GPOLocalGroup" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string11 = " --collectionmethods Group" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string12 = " --collectionmethods LocalGroup" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string13 = " --collectionmethods LoggedOn" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string14 = " --collectionmethods ObjectProps" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string15 = " --collectionmethods PSRemote" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string16 = " --collectionmethods RDP" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string17 = " --collectionmethods Session" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string18 = " --collectionmethods Trusts" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string19 = " --doLocalAdminSessionEnum" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string20 = " --excludedcs" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string21 = /\s\-\-ldapusername\s\s.{0,100}\s\-\-ldappassword\s/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string22 = " --localadminsessionenum " nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string23 = "- --skippasswordcheck" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string24 = " --skipregistryloggedon" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://thedfirreport.com/2024/08/26/blacksuit-ransomware/
        $string25 = /\\"samaccounttype\=268435456\)\(samaccounttype\=268435457\)\(samaccounttype\=536870912\)\(samaccounttype\=536870913\)/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string26 = /\.exe\s\-\-CollectionMethods\sSession\s\-\-Loop/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string27 = /\/SharpHound\.exe/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string28 = /\/SharpHound\-v.{0,100}\.zip/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string29 = /\\SharpHound\.exe/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string30 = /\\SharpHound\.pdb/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string31 = /\\SharpHound\.pdb/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string32 = /\\SharpHoundCommon\\/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string33 = /\\SharpHound\-v.{0,100}\.zip/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string34 = /_SharpHound\-v.{0,100}\.zip/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string35 = ">SharpHound<" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string36 = ">SharpHound<" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string37 = "014b459f4eff259806b56b536fd24475d1824a82213f2b4e174f7650c1cd81db" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string38 = "08896ffbae54cce89cdd8a4158ba8273a4d15c47f87cd8467c778a4000e0b152" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string39 = "0e452eb513a7218f3c9b38ba5e6fd89e3f78fa8ef27996de7e33810302b98bd8" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string40 = "125d8d5718d5ac71f5548f2961980df14595e230c66a5fceada29a7f74af340b" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string41 = "1636247156ec4ac898c680d8b7897c84153f27ef468e6084229fb86f13cbc598" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string42 = "18800661d2b7b1a4c35b64142ba7dc1aee0268a0b6327be86dd9434539e7c53e" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string43 = "19b43b756288d54603b5f435dd5f8a19cba1e3d90db3502246f1d314a917e4b4" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string44 = "1e189b7c760b1ff8db8fdf2290818908dbdad966d74bb77a37dd714f879f4e6f" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string45 = "2016147045d2cbb478945f57bff4c5ce7ae8921c5b5cc996c76df9165b93c9d4" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string46 = "2244c46e179fdec505ac4c6af1725468c69ac6d97526b411ff251098c35948a8" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string47 = "224d47658e0e7ddc256eb97725179a35e42fed02f7717cf5b62afbae26dcb36b" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string48 = "2251b9a7c19ed7f416bdabc535c42682d838e512feef856e7e42c97287a6cd8e" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string49 = "2297be424ff20b0f2e6fdae7e2929014a7eae91cf1743d929c889627a2aae2dd" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string50 = "26733ba4a4306ff57e50790349fca2d49135e8c915fdc608a5600e80b69e1a01" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string51 = "2b6ef9f4b59e06238caf0e4c79e023356784eff5d49313e7fae8539cc47a65ca" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string52 = "2fc6ab3630221478642ba96c1adf85136582e83bf9d935216ed8a7b96343cce1" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string53 = "3002ae0a5cc844b862c99f1d561f9530df8d6259f970d038baeac665a153b91c" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string54 = "31b32d51b5a7d8cd0ca07b410bb0bfd0ff95a92572789788c14b144feb1486c2" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string55 = "33df490ca748ef4411c8423fd6b2b9afa0c120b4faef525ddf2d39bb60001c16" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string56 = "43fab469f6f43d0434dd4cfb16d6719c353618d818ebd2ead0f8a0f23f84e4c3" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string57 = "45adfa7ad271498293d298a774c19e47c94046648c680343b47361fc64bb1fa3" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string58 = "45fd8c64f22872051c84e5c5fe48749ee7ada07a51a1b263dc75c6ccd2567922" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string59 = "51c8d89da154a0d95c49225b7fe712d8e45ecbefd0ba803ab8796c56e86a0e21" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string60 = "570fdc96b43d7e2bc8ee5166053950ff2e235fe741a81ca3733555d1f03a91f7" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string61 = "59eb7b55ff7eb7ca02c78730093c973be826c5516dc32c9ffedd8682e4642264" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string62 = "655d3c2fe42a6d9d46250419d7cd3205efa86f18eb71f9e6285b652ab2fefbde" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string63 = "68c964dff60cd2699cca31430d7ebd494cfc9442a7351512316a4467e19266cd" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string64 = "6964922451227f135e3fce39838f13ba80c0a53e32cd2b66132fb406e1e68411" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string65 = "6dd8dd402142c1671bc971aaa32cdf724daf86ec635b24b7f7f2977da7b349f7" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string66 = "704d20f208c792e1eb4d56521304898839f3cd69d30ad830943c8e2dbe6c85cc" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string67 = "719959af4f0b5b90acacae460e0965e6181766a60a27f536bfae473121a51ff9" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string68 = "7388af6f44132b039881b25fbd8bac9caabee85246196f90c8952c4c25bd8f4d" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string69 = "75935a44f53a44754ff3972fdbc5f0e722ca7aad1f374953fc929c7083b5eae9" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string70 = "78b0faf9c2d4afca5873ccc2f04bf9dbffdf76cf1b854f954d20a7335782ec95" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string71 = "7b0e96b01da4d92b080da542be847cda9320ab3a3260f14c5360a3ceb86b2eb1" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string72 = "7deeafff78ee13e8c4a8073ab7a66265d54b40abeb2bc0691e905176df785401" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string73 = "8221def0e258e6b6b170cc5ea499e9744e527dda36524b06ff2bce9421a70f2e" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string74 = "85aaaf71639238e67726b8e50e29efc74bd78dbbd361c38686e19795aebe34a1" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string75 = "871e9cbecbcdcd82c1a0b696923ef45b8225351e9294ba8086658a28f8b9ac94" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string76 = "87bebb9efbb1fe180ef24187b681894eaf6ce874e7d723299b37d10712b59176" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string77 = "87f65cfedc589113ba5daa88384928e45b4923bd6b9b0fb47e3c112e11fcf353" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string78 = "8c05ab157066ba6d94b843a1eb0732371e23a2feeb2e7522d48e9d421f50ed96" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string79 = "8e1f17fdae5b13fde1ce339439aad3684a758bee89941f69e00d010a6e1bdfbc" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string80 = "90A6822C-4336-433D-923F-F54CE66BA98F" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string81 = "92299f5910a7992534ab33830d9706f4d03798418d5531563a86ee5f4185d553" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string82 = "9a78032821b782755b4990d75b96ee3b77b58021b287d079b831f273e05636a7" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string83 = "9b7a6b25b1f242d4777bbda7ee34d1dab6d0cdcea708c6e0e2fa7ffb4cd9cf7b" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string84 = "9c1a7ef2f61628fc1d314b001169fcc7d2cede2f9ffe07705667ef7151fb014a" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string85 = "9f2cef78b9133cc32d8ef9bb370a0fc73b8bc6a8182519b0715163a816c953ab" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string86 = "a27020a4b91eee6301ac4b67eb12224436692ff4e8bedcfdbe8f31ffb0f4da91" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string87 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string88 = "a5ab019bded982769759606c4e2120bd87f1df5f399baedb739268610df58541" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string89 = "a6f73c1a75d14322aa4993fe498299ab55866ba74440f8a52d4dffe85594de2f" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string90 = "a839c3f26cc75bf3ebc5c8adf91582390c0e625d9c9da30949d968451c6d03dd" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string91 = "aaed9c124d3a6fb221a85b554f6b71dfa58e64838e33454efd59b91675818a38" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string92 = "abb2f26f4a3048ecb57a4329da21ce6fb438c4b22e49a31c0fd23ff4acc1bd68" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string93 = "b1a86d6a5da383a5b86ec8d5a8e49555a233b08079edcc3f31da1b996d008c7b" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string94 = "b2ad37703c99fcd399e6213bd26cbffe2c6a72d5f8d8bc32b455af42fa002fab" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string95 = "b2bb8f3b4b3d50a2a26a0c48fad1a01f9d65ebb7c6a5e6dcd374408fdbc64257" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string96 = "b4ff3bf45fd871b6b6ca158a8890254db5be51ca6aaae3b1559a761caefc80be" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string97 = "b58ac9e4804b66b9a7f7000923454b3b5cabfe991bfb99ae7b6d89fd4b2cab0b" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string98 = "bac48f3c63a2e87f4acf5b6e71fc2e75b22b4a9c197e8a14414f07acd44c3622" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string99 = "bbee76061abd7a8272670354eaa071c698657c4f96f9d6002d36ee8cd234f791" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string100 = "bead5b0e022e634f9f775533f0e7df11aae0e6d1a1616ed7e1bef02abe38ca84" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string101 = "BloodHoundAD" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string102 = /BloodHoundLoopResults\.zip/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string103 = "c4f85b6571f2fe493811418ea62fa29c393799ea3e3cd2ba907b70229a57935d" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string104 = "c58ca5354bbf124feccf0f2347ad5d9a4f2d6a6593b1e4ce71c380e12e9bf1de" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string105 = "c6d9d8cf99b21d48310621c5f02331d0d36253f742ed13f93a4de1db74a668ac" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string106 = "c9dd616338b6ae5e80bb13fdb5474890eea5dec01daad27e519c2981eaaa0dee" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string107 = "cb67da2517b03494285a38806be0aefd25443a3c098227f23023b48d4fa575da" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string108 = "cd8373622b262e9039a6a6ac47046dc6a50464efb807200e7189f7674e0325dd" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string109 = /computerProps\.DumpSMSAPassword/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string110 = "d2e1fecf21091637be0e6d72ad7bca6bfb5e6bb4e59e093bb57907fe3a14c9b6" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string111 = "dbe6ffef155b82e83cf856b5bce79dab6f8f1fcec912274e7a96b477446e3717" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string112 = "dd6e426856acc656cadd4587fa002d4fe50f3370915932256887fa3d9d016687" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string113 = "DisableKerberosSigning" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string114 = "e15d7d10350005b94320906a3f324b1d054509cd3d0795921157daf0cee11e9a" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string115 = "e8764235881acc005589fc1d0e0dce61af095f9d1d6f122bf75fd8b95f4bb368" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string116 = "e8923c77fca2d26eed8cef702814542d9afaebe79797517b7a24b42effc7433a" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string117 = "e99ea45f1119a6feadf8bb999cb8e31705a1d8e0470f39144594aa7496de4895" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string118 = "ea99966d7bb4f887b68d5b318b01d5851e99438426b7b72c65b042a58f3e6ce1" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string119 = "f3c663ef1bce5e962682a498edaeee56b0a68bfd29e193a3e380f1a350b75349" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string120 = "f8596f9a76761fd67a156dc4ab53652ffdf5e2e7b5bcf82a0902099d41d77fbc" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string121 = "fad2d0ab934c4637113555b877e2b3162b0db531baff55f1d4d20567df755d08" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string122 = "fb094bd7cf03a1e0600f9b5efe757443fcd029ba98aabfd3bb6bd3f57c8bb45e" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string123 = "fd2199463d699a530ca73f52434a033fcbcbd7b79b44b078a8461ad8dbdea36f" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string124 = "fe5516f92808349f91469cafff07d9b370f3035e31161ce33f56c08bce13925a" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string125 = "fe8a647aa7f8ac6084ddd7cae6d861a58f2a51620e4d9044b80722b00fe2f2d4" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string126 = "GetDomainsForEnumeration" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string127 = "Initializing SharpHound at " nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string128 = /Initializing\sSharpHound\sat\s\{time\}\son\s\{date\}/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string129 = "Invoke-BloodHound -CollectionMethods " nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string130 = "Invoke-BloodHound" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string131 = "InvokeSharpHound" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string132 = "InvokeSharpHound" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string133 = /Out\-CompressedDll\.ps1/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string134 = /Out\-CompressedDLL\.ps1/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string135 = "Release of BloodHound" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string136 = "running SharpHound" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string137 = /SharpHound\scompleted\s\{Number\}\sloops\!/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string138 = "SharpHound Enumeration Completed at " nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string139 = /SharpHound\-.{0,100}\.zip/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string140 = /sharphound.{0,100}\-\-stealth/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string141 = /sharphound\./ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string142 = /SharpHound\.exe/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string143 = /Sharphound\.Program/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string144 = /sharphound\.ps1/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string145 = /SharpHound\.ps1/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string146 = "SharpHound/releases/download/" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string147 = "SharpHound2" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string148 = "SharpHound3" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string149 = /SharpHoundCommon\./ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string150 = "SharpHoundCommonLib" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string151 = /SharpHoundCommonLib\.dll/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string152 = /SharpHoundCommonLib\.LDAPQueries/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string153 = "SkipPasswordAgeCheck" nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string154 = "SkipPortScan" nocase ascii wide
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
