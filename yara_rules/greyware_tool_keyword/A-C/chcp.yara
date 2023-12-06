rule chcp
{
    meta:
        description = "Detection patterns for the tool 'chcp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chcp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: chcp displays the number of the active console code page
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string1 = /cmd\.exe\s\/c\schcp\s\>\&2/ nocase ascii wide

    condition:
        any of them
}
