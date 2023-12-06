rule EvilSln
{
    meta:
        description = "Detection patterns for the tool 'EvilSln' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilSln"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A New Exploitation Technique for Visual Studio Projects
        // Reference: https://github.com/cjm00n/EvilSln
        $string1 = /\/EvilSln\.git/ nocase ascii wide
        // Description: A New Exploitation Technique for Visual Studio Projects
        // Reference: https://github.com/cjm00n/EvilSln
        $string2 = /\/EvilSln\/.{0,1000}\.suo/ nocase ascii wide
        // Description: A New Exploitation Technique for Visual Studio Projects
        // Reference: https://github.com/cjm00n/EvilSln
        $string3 = /\\EvilSln\\.{0,1000}\.suo/ nocase ascii wide
        // Description: A New Exploitation Technique for Visual Studio Projects
        // Reference: https://github.com/cjm00n/EvilSln
        $string4 = /0FE0D049\-F352\-477D\-BCCD\-ACBF7D4F6F15/ nocase ascii wide
        // Description: A New Exploitation Technique for Visual Studio Projects
        // Reference: https://github.com/cjm00n/EvilSln
        $string5 = /cjm00n\/EvilSln/ nocase ascii wide
        // Description: A New Exploitation Technique for Visual Studio Projects
        // Reference: https://github.com/cjm00n/EvilSln
        $string6 = /EvilSln\-main/ nocase ascii wide

    condition:
        any of them
}
