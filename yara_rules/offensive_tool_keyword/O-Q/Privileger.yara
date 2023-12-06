rule Privileger
{
    meta:
        description = "Detection patterns for the tool 'Privileger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Privileger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string1 = /\/Privileger\.git/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string2 = /MzHmO\/Privileger/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string3 = /Privileger\.cpp/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string4 = /Privileger\.exe/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string5 = /Privileger\-main\./ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string6 = /Privilegerx64\.exe/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string7 = /Privilegerx86\.exe/ nocase ascii wide

    condition:
        any of them
}
