rule LNKUp
{
    meta:
        description = "Detection patterns for the tool 'LNKUp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LNKUp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generates malicious LNK file payloads for data exfiltration
        // Reference: https://github.com/Plazmaz/LNKUp
        $string1 = /\.py\s\-\-host\s.{0,1000}\s\-\-type\sntlm\s\-\-output\s.{0,1000}\.lnk/ nocase ascii wide
        // Description: Generates malicious LNK file payloads for data exfiltration
        // Reference: https://github.com/Plazmaz/LNKUp
        $string2 = /\/LNKUp\.git/ nocase ascii wide
        // Description: Generates malicious LNK file payloads for data exfiltration
        // Reference: https://github.com/Plazmaz/LNKUp
        $string3 = /\/LNKUp\/generate\.py/ nocase ascii wide
        // Description: Generates malicious LNK file payloads for data exfiltration
        // Reference: https://github.com/Plazmaz/LNKUp
        $string4 = /\\LNKUp\\generate\.py/ nocase ascii wide
        // Description: Generates malicious LNK file payloads for data exfiltration
        // Reference: https://github.com/Plazmaz/LNKUp
        $string5 = /lnkup\.py\s\-\-/ nocase ascii wide
        // Description: Generates malicious LNK file payloads for data exfiltration
        // Reference: https://github.com/Plazmaz/LNKUp
        $string6 = /Plazmaz\/LNKUp/ nocase ascii wide

    condition:
        any of them
}
