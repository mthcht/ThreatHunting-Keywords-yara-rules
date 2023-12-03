rule Vajra
{
    meta:
        description = "Detection patterns for the tool 'Vajra' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Vajra"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string1 = /.{0,1000}\/bruteforce\.py.{0,1000}/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string2 = /.{0,1000}\/enumeration\/azureAd\.py.{0,1000}/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string3 = /.{0,1000}\/enumeration\/azureAzService\.py.{0,1000}/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string4 = /.{0,1000}\/enumeration\/subdomain\.py.{0,1000}/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string5 = /.{0,1000}\/enumeration\/userenum\.py.{0,1000}/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string6 = /.{0,1000}\/phishing\.py.{0,1000}/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string7 = /.{0,1000}\/spraying\.py.{0,1000}/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string8 = /.{0,1000}\/TROUBLE\-1\/Vajra.{0,1000}/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string9 = /.{0,1000}\/vajra\/phishApp\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
