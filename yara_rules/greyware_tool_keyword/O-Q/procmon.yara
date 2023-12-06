rule procmon
{
    meta:
        description = "Detection patterns for the tool 'procmon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "procmon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Procmon used in user temp folder
        // Reference: N/A
        $string1 = /\\AppData\\Local\\Temp\\Procmon\.exe/ nocase ascii wide
        // Description: Procmon used in user temp folder
        // Reference: N/A
        $string2 = /\\AppData\\Local\\Temp\\Procmon64\.exe/ nocase ascii wide

    condition:
        any of them
}
