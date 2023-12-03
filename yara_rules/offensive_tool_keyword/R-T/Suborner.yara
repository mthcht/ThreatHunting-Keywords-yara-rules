rule Suborner
{
    meta:
        description = "Detection patterns for the tool 'Suborner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Suborner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string1 = /.{0,1000}\/Suborner\.git.{0,1000}/ nocase ascii wide
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string2 = /.{0,1000}\\Suborner\.sln.{0,1000}/ nocase ascii wide
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string3 = /.{0,1000}r4wd3r\/Suborner.{0,1000}/ nocase ascii wide
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string4 = /.{0,1000}Suborner\.exe.{0,1000}/ nocase ascii wide
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string5 = /.{0,1000}Suborner\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
