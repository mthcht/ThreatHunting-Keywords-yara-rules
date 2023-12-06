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
        $string1 = /\/Suborner\.git/ nocase ascii wide
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string2 = /\\Suborner\.sln/ nocase ascii wide
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string3 = /r4wd3r\/Suborner/ nocase ascii wide
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string4 = /Suborner\.exe/ nocase ascii wide
        // Description: The Invisible Account Forger - A simple program to create a Windows account you will only know about 
        // Reference: https://github.com/r4wd3r/Suborner
        $string5 = /Suborner\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
