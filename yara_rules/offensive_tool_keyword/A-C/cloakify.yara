rule cloakify
{
    meta:
        description = "Detection patterns for the tool 'cloakify' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloakify"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CloakifyFactory & the Cloakify Toolset - Data Exfiltration & Infiltration In Plain Sight. Evade DLP/MLS Devices. Social Engineering of Analysts. Defeat Data Whitelisting Controls. Evade AV Detection. Text-based steganography using lists. Convert any file type (e.g. executables. Office. Zip. images) into a list of everyday strings. Very simple tools. powerful concept. limited only by your imagination.
        // Reference: https://github.com/TryCatchHCF/Cloakify
        $string1 = /cloakify/ nocase ascii wide

    condition:
        any of them
}
