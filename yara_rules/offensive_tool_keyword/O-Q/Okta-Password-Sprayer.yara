rule Okta_Password_Sprayer
{
    meta:
        description = "Detection patterns for the tool 'Okta-Password-Sprayer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Okta-Password-Sprayer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script is a multi-threaded Okta password sprayer.
        // Reference: https://github.com/Rhynorater/Okta-Password-Sprayer
        $string1 = /\/oSpray\.py/ nocase ascii wide
        // Description: This script is a multi-threaded Okta password sprayer.
        // Reference: https://github.com/Rhynorater/Okta-Password-Sprayer
        $string2 = /\\oSpray\.py/ nocase ascii wide
        // Description: This script is a multi-threaded Okta password sprayer.
        // Reference: https://github.com/Rhynorater/Okta-Password-Sprayer
        $string3 = /02024fe8246f659fb6dd07eaf93379e8a8011420d10b83e6bb422b66e53c4292/ nocase ascii wide
        // Description: This script is a multi-threaded Okta password sprayer.
        // Reference: https://github.com/Rhynorater/Okta-Password-Sprayer
        $string4 = /Okta\-Password\-Sprayer/ nocase ascii wide

    condition:
        any of them
}
