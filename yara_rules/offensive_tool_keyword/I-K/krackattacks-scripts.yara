rule krackattacks_scripts
{
    meta:
        description = "Detection patterns for the tool 'krackattacks-scripts' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "krackattacks-scripts"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This project contains scripts to test if clients or access points (APs) are affected by the KRACK attack against WPA2. For details behind this attack see our website and the research paper.
        // Reference: https://github.com/vanhoefm/krackattacks-scripts
        $string1 = /.{0,1000}krackattacks.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
