rule bitsadmin
{
    meta:
        description = "Detection patterns for the tool 'bitsadmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitsadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: bitsadmin suspicious transfer
        // Reference: N/A
        $string1 = /bitsadmin\s\/transfer\sdebjob\s\/download\s\/priority\snormal\s\\.{0,1000}\\C\$\\Windows\\.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}
