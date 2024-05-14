rule arsenal
{
    meta:
        description = "Detection patterns for the tool 'arsenal' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "arsenal"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string1 = /\sarsenal\-master\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string2 = /\s\-\-asreproast/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string3 = /\sGetNPUsers\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string4 = /\sgoldenPac\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string5 = /\sHostRecon\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string6 = /\sinstall\sarsenal\-cli/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string7 = /\s\-jar\sysoserial\.jar/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string8 = /\s\-\-kerberoasting/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string9 = /\sldapsearch\-ad\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string10 = /\smsfstaged\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string11 = /\s\-\-no\-bruteforce\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string12 = /\sprinterbug\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string13 = /\sPrivescCheck\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string14 = /\s\-\-rid\-brute\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string15 = /\stheHarvester\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string16 = /\sticketConverter\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string17 = /\s\-\-trusted\-for\-delegation\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string18 = /\.arsenal\.json/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string19 = /\/arsenal\.git/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string20 = /\/arsenal\-1\.1\.0\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string21 = /\/arsenal\-1\.2\.0\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string22 = /\/arsenal\-1\.2\.1\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string23 = /\/arsenal\-master\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string24 = /\/GetNPUsers\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string25 = /\/goldenPac\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string26 = /\/HostRecon\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string27 = /\/kerberoastables\.txt/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string28 = /\/lazagne\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string29 = /\/ldapsearch\-ad\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string30 = /\/msfnonstaged\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string31 = /\/msfstaged\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string32 = /\/owa\-valid\-users\.txt/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string33 = /\/payload\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string34 = /\/powerview\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string35 = /\/printerbug\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string36 = /\/PrivescCheck\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string37 = /\/privexchange\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string38 = /\/ruler\s\-k\s\-d\s.{0,1000}\sdump\s\-o\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string39 = /\/spray\-results\.txt/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string40 = /\/theHarvester\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string41 = /\/ticketConverter\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string42 = /\/ticketer\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string43 = /\/ysoserial\.jar/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string44 = /\\\\\.\\pipe\\test\\pipe\\spoolss\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string45 = /\\arsenal\-1\.1\.0\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string46 = /\\arsenal\-1\.2\.0\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string47 = /\\arsenal\-1\.2\.1\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string48 = /\\arsenal\-master\.zip/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string49 = /\\chisel\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string50 = /\\GetNPUsers\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string51 = /\\goldenPac\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string52 = /\\HostRecon\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string53 = /\\kerberoastables\.txt/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string54 = /\\lazagne\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string55 = /\\ldapsearch\-ad\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string56 = /\\msfnonstaged\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string57 = /\\msfstaged\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string58 = /\\owa\-valid\-users\.txt/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string59 = /\\payload\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string60 = /\\printerbug\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string61 = /\\PrivescCheck\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string62 = /\\privexchange\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string63 = /\\sharprdp\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string64 = /\\spray\-results\.txt/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string65 = /0aebcf5b97bf1ae6286c7aa7000f1ee68b063bd9ded6c871c708c8e639793c3f/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string66 = /1372ebd0f43824ac646712ab9b47a28938e2b58eb1dce8337c1d905dea0f7523/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string67 = /1753bd59904f52ea9be59524942fc98321472c6a91c7af8051ab397edee32e6a/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string68 = /2366491D74D80C76F75A7F84ABF82C1E88518A615CB2332FDCC846181F60AEAE/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string69 = /32A26CB8E0ECA88CA6116E467FC8BD5430E54133A5642ED1AFED8DCC2B9C9DFD/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string70 = /32ccdc0e660f56052d82e4e5788c7d555d7dfcf00d3949dfd98d69a9803619c0/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string71 = /420e9c27a22ad9c6cb1535009bc23440b7a54fbef61d30e0702926e6a03502d3/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string72 = /42d19694b284a82d02a8662edb4db86c22122ea981ca36aced94c4ba67fff072/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string73 = /5bfec4da2bd86d19199d74b0b95f044a2dc4ef0fc40941315b0d0ac49e6fb890/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string74 = /60de3c5fb9a9dcab760da4377992481cb707fb5c1a633be197c332163b37919b/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string75 = /6b9093336ef9693a155bf5b514705424177b9d48679ddb809d18a75501c1041f/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string76 = /72b2d05cbbdea293859fc1a06651a3932c4b72675a0e014ad91a3b413cbd15c4/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string77 = /7734774a6bbb47e7c0f32f4903928df120887180ddae7bb2bd4d15cd17a4a7c1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string78 = /8c71bcc0680bd7c69fd58639a6748d26202caab6d639f9b92eb394e6648bce0e/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string79 = /95dd437c805fb71cb3cda5f20ad9b212c44f14dc09194867125acb289af6301b/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string80 = /a43f8c6f567c0280ddb10660ab9a00f492741d3c4e668c2ca8ea171dc30cb083/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string81 = /Arsenal\sneeds\sTIOCSTI\senable\sfor\srunning/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string82 = /arsenal\sv.{0,1000}\s\-\sPentest\scommand\slauncher/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string83 = /ASREProastables\.txt/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string84 = /b1ba3cccf93baf069e6502bc75d033bcb519fd7209be70eec7f0743db81b6650/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string85 = /b55dd8b809ebb71681cb09b07d6def2ea453d36d25c2a74a4ecac7662c3ddbbd/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string86 = /c0847034ecb624fde98700f4866d0a3fb799d3ff601ccd56df5bf31a9c065a53/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string87 = /C2DAC5B0DBA2FC51AAA3FAF6AA1372E43D7A2B33F288FCEC5ADD4B7360440DBA/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string88 = /c5d484d2c6817bbf05a900cd6bced458311b72af57d14b29421816620769f4ac/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string89 = /c730a89142b73d047b4387f6f3f0d8dfacef57a2e4945a0a942cc72f0bd05253/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string90 = /d3290c562ad2740c0ddfd8cee2c2239055cf1491f54127f48a4e64549145c6e5/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string91 = /dc9eb5bb3d882cb0ee30fd21ecbbb030e4e0367dff16b06109bfcfc40fef112/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string92 = /dd962b2de10f0a44beb1483ef05afce58151e471e9d0b79b7388f663292fd634/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string93 = /enumdomains\;quit/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string94 = /enumdomgroups\;quit/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string95 = /enumdomusers\;quit/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string96 = /f923e44f1665a3cbae86b73bc2d3dcd74e928a7f358b75bb6dc/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string97 = /fb4a9c6269ea58b893c6978105fd3e2b2bc6e72e24715c1824b45f40c87b850d/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string98 = /GetUserSPNs\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string99 = /GetUserSPNs\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string100 = /GetUserSPNs\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string101 = /getusrdompwinfo\s.{0,1000}\;quit/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string102 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string103 = /kiwi_cmd.{0,1000}\/process\:lsass\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string104 = /LAPSToolkit\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string105 = /mimikatz\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string106 = /msfstaged\.exe\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string107 = /ntlmrelayx\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string108 = /Orange\-Cyberdefense\/arsenal/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string109 = /PetitPotam\.py/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string110 = /post\/windows\/gather\/credentials\/vnc/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string111 = /PrintSpooferNet\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string112 = /privexchange\.py\s\-d\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string113 = /procdump\.exe\s\-accepteula\s\-ma\slsass\.exe/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string114 = /python\s\-m\speas\s\-u\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string115 = /ruler\s\-k\s\-\-nocache\s\-\-url\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string116 = /SharpHound\.ps1/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string117 = /theHarvester\.py\s\-d\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string118 = /use\sexploit\/windows\// nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string119 = /Use\snmap\s\-\-script\shttp\-ntlm\-info\s/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string120 = /use\sscanner\/smb\/smb_enum_gpp/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string121 = /use\sscanner\/ssh\/ssh_enumusers/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string122 = /VirTool\:PowerShell\/Scanpatch\.A/ nocase ascii wide
        // Description: Arsenal is just a quick inventory and launcher for hacking programs
        // Reference: https://github.com/Orange-Cyberdefense/arsenal
        $string123 = /ysoserial\.exe/ nocase ascii wide

    condition:
        any of them
}
