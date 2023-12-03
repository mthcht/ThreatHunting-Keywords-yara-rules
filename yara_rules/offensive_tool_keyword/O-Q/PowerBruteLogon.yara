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
        $string1 = /.{0,1000}\/PowerBruteLogon.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string2 = /.{0,1000}Invoke\-BruteAvailableLogons.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string3 = /.{0,1000}Invoke\-BruteLogonAccount.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string4 = /.{0,1000}Invoke\-BruteLogonList.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string5 = /.{0,1000}PowerBruteLogon\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
