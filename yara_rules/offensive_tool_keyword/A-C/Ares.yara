rule Ares
{
    meta:
        description = "Detection patterns for the tool 'Ares' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ares"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string1 = /\s0\.0\.0\.0\:8080\s\-\-threads/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string2 = /\shttp\:\/\/localhost\:8080\s\-o\sagent/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string3 = /\/Ares\.git/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string4 = /\/ares\.py\s/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string5 = /ares\.py\srunserver/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string6 = /ares\-master\.zip/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string7 = /autostart\/ares\.desktop/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string8 = /gunicorn\sares\:app/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string9 = /sqlite\:\/\/\/ares\.db/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string10 = /sweetsoftware\/Ares/ nocase ascii wide

    condition:
        any of them
}
