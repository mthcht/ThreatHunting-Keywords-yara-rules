rule EvilnoVNC
{
    meta:
        description = "Detection patterns for the tool 'EvilnoVNC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilnoVNC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string1 = /\/EvilnoVNC\.git/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string2 = /\\EvilnoVNC/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string3 = /\\Keylogger\.txt/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string4 = /EvilnoVNC\-main/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string5 = /JoelGMSec\/EvilnoVNC/ nocase ascii wide

    condition:
        any of them
}