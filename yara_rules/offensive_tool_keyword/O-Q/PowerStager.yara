rule PowerStager
{
    meta:
        description = "Detection patterns for the tool 'PowerStager' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerStager"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerStager: This script creates an executable stager that downloads a selected powershell payload.
        // Reference: https://github.com/z0noxz/powerstager
        $string1 = /powerstager/ nocase ascii wide

    condition:
        any of them
}
