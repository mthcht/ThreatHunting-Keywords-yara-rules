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
        $string1 = /\/AndrewSpecial\.git/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string2 = /\\Andrew\.dmp/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string3 = /AndrewSpecial\.cpp/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string4 = /AndrewSpecial\.exe/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string5 = /AndrewSpecial\-master/ nocase ascii wide
        // Description: AndrewSpecial - dumping lsass memory stealthily
        // Reference: https://github.com/hoangprod/AndrewSpecial
        $string6 = /hoangprod\/AndrewSpecial/ nocase ascii wide

    condition:
        any of them
}
