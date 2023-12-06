rule Red_Teaming_Toolkit
{
    meta:
        description = "Detection patterns for the tool 'Red-Teaming-Toolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Red-Teaming-Toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of open source and commercial tools that aid in red team operations. This repository will help you during red team engagement. If you want to contribute to this list send me a pull request
        // Reference: https://github.com/infosecn1nja/Red-Teaming-Toolkit
        $string1 = /Red\-Teaming\-Toolkit/ nocase ascii wide

    condition:
        any of them
}
