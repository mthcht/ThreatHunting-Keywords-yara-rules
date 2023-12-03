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
        $string1 = /.{0,1000}\s0\.0\.0\.0:8080\s\-\-threads.{0,1000}/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string2 = /.{0,1000}\shttp:\/\/localhost:8080\s\-o\sagent.{0,1000}/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string3 = /.{0,1000}\/Ares\.git/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string4 = /.{0,1000}\/ares\.py\s.{0,1000}/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string5 = /.{0,1000}ares\.py\srunserver.{0,1000}/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string6 = /.{0,1000}ares\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string7 = /.{0,1000}autostart\/ares\.desktop.{0,1000}/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string8 = /.{0,1000}gunicorn\sares:app.{0,1000}/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string9 = /.{0,1000}sqlite:\/\/\/ares\.db.{0,1000}/ nocase ascii wide
        // Description: Python C2 botnet and backdoor 
        // Reference: https://github.com/sweetsoftware/Ares
        $string10 = /.{0,1000}sweetsoftware\/Ares.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
