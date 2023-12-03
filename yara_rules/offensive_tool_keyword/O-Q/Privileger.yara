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
        $string1 = /.{0,1000}\/Privileger\.git.{0,1000}/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string2 = /.{0,1000}MzHmO\/Privileger.{0,1000}/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string3 = /.{0,1000}Privileger\.cpp.{0,1000}/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string4 = /.{0,1000}Privileger\.exe.{0,1000}/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string5 = /.{0,1000}Privileger\-main\..{0,1000}/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string6 = /.{0,1000}Privilegerx64\.exe.{0,1000}/ nocase ascii wide
        // Description: Privileger is a tool to work with Windows Privileges
        // Reference: https://github.com/MzHmO/Privileger
        $string7 = /.{0,1000}Privilegerx86\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
