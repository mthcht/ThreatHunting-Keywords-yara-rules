rule touch
{
    meta:
        description = "Detection patterns for the tool 'touch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "touch"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
        $string1 = /touch\s\-a/ nocase ascii wide
        // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
        $string2 = /touch\s\-m/ nocase ascii wide
        // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
        $string3 = /touch\s\-r\s/ nocase ascii wide
        // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
        $string4 = /touch\s\-t\s/ nocase ascii wide

    condition:
        any of them
}