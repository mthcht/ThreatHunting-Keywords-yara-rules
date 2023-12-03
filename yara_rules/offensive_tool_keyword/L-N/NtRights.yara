rule NtRights
{
    meta:
        description = "Detection patterns for the tool 'NtRights' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtRights"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tool for adding privileges from the commandline
        // Reference: https://github.com/gtworek/PSBits/tree/master/NtRights
        $string1 = /.{0,1000}\/NtRights\/.{0,1000}/ nocase ascii wide
        // Description: tool for adding privileges from the commandline
        // Reference: https://github.com/gtworek/PSBits/tree/master/NtRights
        $string2 = /.{0,1000}\\NtRights\\.{0,1000}/ nocase ascii wide
        // Description: tool for adding privileges from the commandline
        // Reference: https://github.com/gtworek/PSBits/tree/master/NtRights
        $string3 = /.{0,1000}ntrights\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
