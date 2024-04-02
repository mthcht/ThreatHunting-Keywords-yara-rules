rule NLBrute
{
    meta:
        description = "Detection patterns for the tool 'NLBrute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NLBrute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string1 = /\/NLBrute.{0,1000}\.rar/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string2 = /\/NLBrute.{0,1000}\.zip/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string3 = /\/NLBrute\.exe/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string4 = /\[Reflection\.Assembly\]\:\:Load\(.{0,1000}\[Char\]\(.{0,1000}\)\+\[Char\]\(.{0,1000}\)\+.{0,1000}\+\[Char\]\(.{0,1000}\)/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string5 = /\\NLBrute.{0,1000}\.rar/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string6 = /\\NLBrute.{0,1000}\.zip/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string7 = /\\NLBrute\.exe/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string8 = /2f40452382f378c481ce9622ea6f10cfb0275cad138c6a45fe16144111fdfa77/ nocase ascii wide
        // Description: RDP Bruteforcer
        // Reference: https://github.com/amazond/NLBrute-1.2
        $string9 = /4781b10d0dae27a772518c9167b3a654c46017897bc73ce4540f4bfca33e9b58/ nocase ascii wide

    condition:
        any of them
}
