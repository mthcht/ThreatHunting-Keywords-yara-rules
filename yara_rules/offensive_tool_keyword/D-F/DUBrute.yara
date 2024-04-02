rule DUBrute
{
    meta:
        description = "Detection patterns for the tool 'DUBrute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DUBrute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string1 = /\/DUBrute\.git/ nocase ascii wide
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string2 = /ch0sys\/DUBrute/ nocase ascii wide
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string3 = /Create\s\%d\sIP\@Loginl\;Password/ nocase ascii wide
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string4 = /d53fb2aa459eb50e3d16f17835db3246e3016389cfa63c126263e24fa18729e7/ nocase ascii wide
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string5 = /DuBrute\sv/ nocase ascii wide
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string6 = /dubrute\.exe/ nocase ascii wide
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string7 = /DUBrute_v/ nocase ascii wide
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string8 = /Generator\sIP\@Login\;Password/ nocase ascii wide
        // Description: RDP  Bruteforcer
        // Reference: https://github.com/ch0sys/DUBrute
        $string9 = /Hacked\sby\sSkenda\sUnikkatil/ nocase ascii wide

    condition:
        any of them
}
