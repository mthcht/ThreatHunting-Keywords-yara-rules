rule SharpPack
{
    meta:
        description = "Detection patterns for the tool 'SharpPack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpPack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string1 = /\.exe\saction\=executevbs\scomputername\=/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string2 = /\.exe\sasreproast\s\// nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string3 = /\.exe\screatenetonly\s\/program\:/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string4 = /\.exe\skerberoast\s\/domain/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string5 = /\/MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string6 = /\/SharpPack\.git/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string7 = ": Running Privilege Escalation Checks ===" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string8 = /\[IO\.File\]\:\:WriteAllBytes\(\\".{0,100}\.kirbi/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string9 = /\[X\]\sNo\susers\sfound\sto\sKerberoast\!/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string10 = /\[X\]\sYou\sneed\sto\sbe\sin\shigh\sintegrity\sto\sapply\sa\sticket\sto\sa\sdifferent\slogon\ssession/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string11 = /\\CSExec\-master\\/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string12 = /\\csexecsvc\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string13 = /\\csexecsvc\-net35\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string14 = /\\csexecsvc\-net40\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string15 = /\\csexecsvc\-net45\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string16 = /\\Debug\\SharpDump\.pdb/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string17 = /\\Debug\\SharpRoast\.pdb/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string18 = /\\Debug\\SharpWMI\.pdb/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string19 = /\\powerkatz_x64\.dll/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string20 = /\\powerkatz_x86\.dll/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string21 = /\\Release\\SharpCradle\.pdb/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string22 = /\\Release\\SharpSploitConsole\.pdb/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string23 = /\\Release\\SharpView\.pdb/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string24 = /\\Rubeus\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string25 = /\\rubeus\.txt/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string26 = /\\SharpChrome\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string27 = /\\SharpDPAPI\.txt/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string28 = /\\SharpPack\-master/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string29 = /\\SharpSploit\.dll/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string30 = /\\SharpSql\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string31 = /\\SharpWMI\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string32 = "=== Cached GPP Password ===" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string33 = "=== SharpUp: Running Privilege Escalation Checks ===" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string34 = ">SafetyKatz<" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string35 = ">SharpRoast<" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string36 = ">SharpSQL<" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string37 = ">SharpView<" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string38 = ">SharpWMI<" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string39 = "0a140743a725d685faa98e11f0d34ab19c9531c50ac57c8b1ddbfa683057519d" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string40 = "0a7cf0b0d8f68eec8829dde1d90183087d641547a6c97de021db9a631da99857" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string41 = "0f99d2f2523047aa778e196a7f0bfd83580b3faa94299c52502d205957d23e5f" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string42 = "0fcb623d8d52c2357fb23ea4eb62a1553761faec062c084179e0211ec725a837" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string43 = "2273ad36e35b7acbbc7ff15649c2ed3683c7d1c35f12f33e41019744be19029a" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string44 = "22A156EA-2623-45C7-8E50-E864D9FC44D3" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string45 = "291a6968a3f7f2092c656d0275c604182d6f7ee7b813460aeb8b28c06d804b5e" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string46 = "2a90167209fbc5f0a2af9666eeeb1947c925efe72537e7bea4a384e8159777f1" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string47 = "2ed2e8804392510f60bd52822e068a73fd5be02852694258f88d9dec7917e107" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string48 = "2F00A05B-263D-4FCC-846B-DA82BD684603" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string49 = "326e22bdce3db54f97f230ad600f03908f9a582944d481f293cd7013ce2e8567" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string50 = "326e22bdce3db54f97f230ad600f03908f9a582944d481f293cd7013ce2e8567" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string51 = "326e22bdce3db54f97f230ad600f03908f9a582944d481f293cd7013ce2e8567" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string52 = "35aa30b42ea12208cfad81a29831d88d0a778ab192186c516d89e1c9f538a285" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string53 = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string54 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD753" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string55 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD754" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string56 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD755" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string57 = "4aea1d1fd9ccaeb832026cadde29adfc5bc5a566e423b201747b101c8ca4281c" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string58 = "51ed625d1ce0d7de0a2cb6b61254c926154edd760f596eba6ef8bc6a50242108" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string59 = "51ed625d1ce0d7de0a2cb6b61254c926154edd760f596eba6ef8bc6a50242108" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string60 = "53ef805c456f2b3312be89695e41cc4693cf6fe169388c32aedb207e1d3a6a6b" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string61 = "55e85cf923faed84769d3b61cd10bb2d444edb20ffaf1cbfd5af304d6add3cdd" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string62 = "58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string63 = "58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string64 = "58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string65 = "58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string66 = "58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string67 = "58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string68 = "58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string69 = "5da47804835b0d8e787353d8660ada4903f9971aafa864d651bf7ccdec3ee16d" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string70 = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string71 = "5fcda49ee7f202559a6cbbb34edb65c33c9a1e0bde9fa2af06a6f11b55ded619" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string72 = "64fc0afc72a37b1071482e9c4725cd35fa2b974c6903cd01124ed7fe9d2c8e27" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string73 = "6511e5a343746d582d9e5f598ac329eb56ccde68429c880b1a9e551f5c27083d" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string74 = "658C8B7F-3664-4A95-9572-A3E5871DFC06" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string75 = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string76 = "759531afaa67180eb431415b0961e4da1792653b637edd0c97c086672cdbb2dd" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string77 = "77025f0392d2811d58e8835a03671c0cbbf40f112f1c9cf3c6e864fdb1effa0a" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string78 = "7760248F-9247-4206-BE42-A6952AA46DA2" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string79 = "79C9BBA3-A0EA-431C-866C-77004802D8A0" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string80 = "8337460fcc31ae6781de16482287810dcefc051e15cd18a28af46654b3ab7b4b" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string81 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string82 = "8694c7e87215c274f09116eb2f13cd23cf847abc46a25977088873b0d353c368" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string83 = "8d525a86500b6ebf3618e9f9f5fd861cdf6a8318dba28acfa95a5c725239d015" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string84 = "8fc36834909b236d10cf316bb5c265745c022e94708b8d759c6d20ee25c3e436" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string85 = "8fc36834909b236d10cf316bb5c265745c022e94708b8d759c6d20ee25c3e436" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string86 = "957a85413b6979ee849ae5b802066eeab409bef45da76540a8d6f561bc0a36a0" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string87 = "96e38545cc3afc9f9acfbe1e34537d0c8dd13c4684c60e563051fe9fe462db5e" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string88 = "9734db4d2d53bb15ae0f8214595a7a781df78445811dd5d1a16319dea549ea39" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string89 = "9a83ec1bf3e113300930a7cc5d1259ef87bd85a428e3ede47104906ba3ac9fa6" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string90 = "9a83ec1bf3e113300930a7cc5d1259ef87bd85a428e3ede47104906ba3ac9fa6" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string91 = "a8ddc05a5d82ab6abbf4f329fb508e1025a7dceabbe76d3639156009247792ea" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string92 = /ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string93 = "adeb6e60c4b8f102216d935dfa9dfe6cf53988fe41f9418fdb5674b5adadbf65" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string94 = "adeb6e60c4b8f102216d935dfa9dfe6cf53988fe41f9418fdb5674b5adadbf65" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string95 = "adeb6e60c4b8f102216d935dfa9dfe6cf53988fe41f9418fdb5674b5adadbf65" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string96 = "AEC32155-D589-4150-8FE7-2900DF4554C8" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string97 = "b33858d4365b180692b8dd37ce721ffab80d6953a3a1505a6e56973b63c2520d" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string98 = "B59C7741-D522-4A41-BF4D-9BADDDEBB84A" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string99 = "b6575fb3abada109a6d35ce04e8ff89e07ba765659724536e9a04921bc0dc196" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string100 = "c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string101 = "c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string102 = "c84f6dc3572924ef262bdef54962e03099ca54cab7f27cf1b9112b00c4ff95e9" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string103 = "c9978b0c3712e43f8e102dbff7ee57f7d59f38d5d17b0304bd691ba1c53a8893" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string104 = "caf9a055f2ff381b97c14536634a3bda03c79b47402719bfe8145b3285351450" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string105 = "caf9a055f2ff381b97c14536634a3bda03c79b47402719bfe8145b3285351450" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string106 = "d653c01c040b025f77eda69eaff1b33f0e1f8542fc409dd42e936e35de22ff97" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string107 = "d9b74200f9ac68b21bf978956eceaaf1ac34f96a47833928714b8f1857bccf2b" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string108 = "e82a9d963a5752b034523b96ee1702ba733c83ca2f00bb3aa190254e8967646a" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string109 = "efe57ef897c458aef4650ca14d21160c6e685441c0b71de67b22cbe19d4ca3f1" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string110 = "efe57ef897c458aef4650ca14d21160c6e685441c0b71de67b22cbe19d4ca3f1" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string111 = "Elevating to SYSTEM via token duplication for LSA secret retrieval" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string112 = /extracts\sthe\sAES\s128\/256\skeys\sfrom\sPolicy\.vpol/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string113 = "F3037587-1A3B-41F1-AA71-B026EFDB2A35" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string114 = "F3037587-1A3B-41F1-AA71-B026EFDB2A40" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string115 = "F3037587-1A3B-41F1-AA71-B026EFDB2A45" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string116 = "F70D2B71-4AAE-4B24-9DAE-55BC819C78BB" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string117 = "FD6BDF7A-FEF4-4B28-9027-5BF750F08048" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string118 = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string119 = "get_csexecsvc_net35" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string120 = "get_csexecsvc_net40" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string121 = "get_csexecsvc_net45" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string122 = /https\:\/\/github\.com\/threatexpress\/red\-team\-scripts\/blob\/master\/HostEnum\.ps1/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string123 = /https\:\/\/sharpsploit\.cobbr\.io\/api/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string124 = "In medium integrity but user is a local administrator- UAC can be bypassed" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string125 = "Lexus89/SharpPack" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string126 = /Misc\-Powershell\-Scripts\/blob\/master\/Invoke\-DCOM\.ps1/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string127 = /Misc\-PowerShell\-Stuff\/blob\/master\/Invoke\-TokenDuplication\.ps1/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string128 = "Not in high integrity, unable to MiniDump!" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string129 = "Roast a specific specific SPN" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string130 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string131 = "Searching for accounts that only support RC4_HMAC" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string132 = /SeatBelt\.exe\ssystem/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string133 = "SharpChrome backupkey " nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string134 = /SharpCradle\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string135 = "SharpDPAPI backupkey " nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string136 = /SharpDPAPI\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string137 = /SharpDump\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string138 = /SharpRoast\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string139 = "SharpSploit Domain Enumeration Commands" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string140 = /SharpSploit\.Credentials\./ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string141 = /SharpSploit\.Enumeration\./ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string142 = /SharpSploit\.Exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string143 = /sharpSploitConsole\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string144 = /SharpSploitConsole_x64\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string145 = /SharpUp\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string146 = /Sharpview\.exe/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string147 = /SharpWMI\.exe\saction\=/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string148 = /UACEnum\.SCR/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string149 = /using\sSharpSploit\.Credentials/ nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string150 = "Written by anthemtotheego & g0ldengunsec" nocase ascii wide
        // Description: collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // Reference: https://github.com/Lexus89/SharpPack
        $string151 = "You need to be in high integrity to extract LSA secrets!" nocase ascii wide
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
