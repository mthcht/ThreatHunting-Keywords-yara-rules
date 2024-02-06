rule ntpescape
{
    meta:
        description = "Detection patterns for the tool 'ntpescape' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntpescape"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string1 = /\s\|\s\.\/send\s\-d\s.{0,1000}\:123\s\-tM\s0\s\-tm\s0/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string2 = /\.\/recv\s\-d\s\:50001/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string3 = /\.\/send\s\-d\s.{0,1000}\:123\s\-f\s/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string4 = /\/ntpescape\.git/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string5 = /evallen\/ntpescape/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string6 = /ntpescape.{0,1000}recv/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string7 = /ntpescape.{0,1000}send/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string8 = /ntpescape\-master\./ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string9 = /sudo\s\.\/recv\s\-f\s/ nocase ascii wide

    condition:
        any of them
}
