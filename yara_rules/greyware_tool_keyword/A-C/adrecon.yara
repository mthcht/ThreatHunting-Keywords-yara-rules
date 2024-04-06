rule adrecon
{
    meta:
        description = "Detection patterns for the tool 'adrecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adrecon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string1 = /ADRecon\s\-OutputDir\s/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string2 = /ADRecon\.ps1/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string3 = /ADRecon\-Report\-/ nocase ascii wide

    condition:
        any of them
}
