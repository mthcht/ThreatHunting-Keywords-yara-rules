rule o365_attack_toolkit
{
    meta:
        description = "Detection patterns for the tool 'o365-attack-toolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365-attack-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A toolkit to attack Office365
        // Reference: https://github.com/mdsecactivebreach/o365-attack-toolkit
        $string1 = /.{0,1000}http:\/\/localhost:30662.{0,1000}/ nocase ascii wide
        // Description: A toolkit to attack Office365
        // Reference: https://github.com/mdsecactivebreach/o365-attack-toolkit
        $string2 = /.{0,1000}o365\-attack\-toolkit.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
