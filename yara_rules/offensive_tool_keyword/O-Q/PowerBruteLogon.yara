rule PowerBruteLogon
{
    meta:
        description = "Detection patterns for the tool 'PowerBruteLogon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerBruteLogon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string1 = /\/PowerBruteLogon/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string2 = /Invoke\-BruteAvailableLogons/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string3 = /Invoke\-BruteLogonAccount/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string4 = /Invoke\-BruteLogonList/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string5 = /PowerBruteLogon\./ nocase ascii wide

    condition:
        any of them
}
