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
        $string1 = /\/bruteforce\.py/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string2 = /\/enumeration\/azureAd\.py/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string3 = /\/enumeration\/azureAzService\.py/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string4 = /\/enumeration\/subdomain\.py/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string5 = /\/enumeration\/userenum\.py/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string6 = /\/phishing\.py/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string7 = /\/spraying\.py/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string8 = /\/TROUBLE\-1\/Vajra/ nocase ascii wide
        // Description: Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment
        // Reference: https://github.com/TROUBLE-1/Vajra
        $string9 = /\/vajra\/phishApp\.py/ nocase ascii wide

    condition:
        any of them
}
