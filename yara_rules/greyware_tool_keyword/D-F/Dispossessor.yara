rule Dispossessor
{
    meta:
        description = "Detection patterns for the tool 'Dispossessor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dispossessor"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: tool used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = /\\BEST_uninstallTool\.exe/ nocase ascii wide
        // Description: powershell script to find a spn - abused by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = /\\findspn\.ps1/ nocase ascii wide

    condition:
        any of them
}
