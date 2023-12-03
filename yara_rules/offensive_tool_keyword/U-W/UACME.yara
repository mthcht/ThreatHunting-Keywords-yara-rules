rule UACME
{
    meta:
        description = "Detection patterns for the tool 'UACME' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UACME"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string1 = /.{0,1000}\/UACME\.git.{0,1000}/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string2 = /.{0,1000}\\UACME\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string3 = /.{0,1000}hfiref0x\/UACME.{0,1000}/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string4 = /.{0,1000}UACME\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
