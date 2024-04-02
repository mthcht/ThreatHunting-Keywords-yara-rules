rule adget
{
    meta:
        description = "Detection patterns for the tool 'adget' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adget"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: gather valuable informations about the AD environment
        // Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
        $string1 = /\/ADGet\.exe/ nocase ascii wide
        // Description: gather valuable informations about the AD environment
        // Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
        $string2 = /\\ADGet\.exe/ nocase ascii wide

    condition:
        any of them
}
