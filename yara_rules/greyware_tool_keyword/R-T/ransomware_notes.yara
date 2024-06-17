rule ransomware_notes
{
    meta:
        description = "Detection patterns for the tool 'ransomware_notes' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ransomware_notes"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string1 = /https\:\/\/gofile\.io\/d\// nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string2 = /https\:\/\/tox\.chat\/download\.html/ nocase ascii wide

    condition:
        any of them
}
