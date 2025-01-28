rule SomalifuscatorV2
{
    meta:
        description = "Detection patterns for the tool 'SomalifuscatorV2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SomalifuscatorV2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string1 = /\/anti_methods\/antivm\.ps1/ nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string2 = /\/SomalifuscatorV2\.git/ nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string3 = /\\\\Users\\\\Public\\\\quran\.txt/ nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string4 = /\\anti_methods\\antivm\.ps1/ nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string5 = /\\somalifuscatorv2\.log/ nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string6 = /\\Users\\Public\\quran\.txt/ nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string7 = "0988d2c24c478d4918d1aebd99817d7d84d0a6997fffed713fada3338636b62a" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string8 = "1de7f78ed7238628f18928f1ba7a499e0aa844870865661110db15ed1cb3a1d5" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string9 = "4bd26151318dad8f056062ca75ccffccda34afc9edea03f6dd5056bc9a961996" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string10 = "63c026b6e54d35d2c987267fd01894021efea0f83a87e98c142b96f10f301914" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string11 = "846994e23ac384d930d24bc63ad2094bf6565a7ece8a14858d256124a5bfa817" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string12 = "beb9a98df0d88653ba149728d157a519df367a2015fd2d120daeef988027ba6f" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string13 = "d71e7b439225124e610f0a5faa4a8170961d5ed80088144a1326db7e661cf646" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string14 = /echo\s\%cmdcmdline\%\s\|\sfind\s\/i\s\\"\%\~f0\\"\>nul\s\|\|\sexit\s\/b\s1/
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string15 = /https\:\/\/raw\.githubusercontent\.com\/KDot227\// nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string16 = /https\:\/\/sped\.lol\// nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string17 = "JAB1AHIAbAAgAD0AIAAnAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8ASwBEAG8AdAAyADIANwAvA" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string18 = "KDot227/SomalifuscatorV2" nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string19 = /pc_ip\s\=\sInvoke\-WebRequest\s\-Uri\s\\"https\:\/\/api\.ipify\.org\\"\s\-UseBasicParsing/ nocase ascii wide
        // Description: windows batch obfuscator
        // Reference: https://github.com/KDot227/SomalifuscatorV2
        $string20 = /raw\.githubusercontent\.com\/6nz\/virustotal\-vm\-blacklist\// nocase ascii wide

    condition:
        any of them
}
