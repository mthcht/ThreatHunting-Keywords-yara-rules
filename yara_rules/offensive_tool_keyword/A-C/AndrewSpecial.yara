rule AndrewSpecial
{
    meta:
        description = "Detection patterns for the tool 'AndrewSpecial' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AndrewSpecial"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string1 = /.{0,1000}\/AndrewSpecial\.git.{0,1000}/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string2 = /.{0,1000}\\Andrew\.dmp.{0,1000}/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string3 = /.{0,1000}AndrewSpecial\.cpp.{0,1000}/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string4 = /.{0,1000}AndrewSpecial\.exe.{0,1000}/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string5 = /.{0,1000}AndrewSpecial\-master.{0,1000}/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string6 = /.{0,1000}hoangprod\/AndrewSpecial.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
