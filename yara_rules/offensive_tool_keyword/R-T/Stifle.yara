rule Stifle
{
    meta:
        description = "Detection patterns for the tool 'Stifle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stifle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string1 = /\\tStifle\.exe/ nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string2 = "186789b7b7c4973d4f941582a796c3ced5ae7fbc4527cf19040e740d380c4106" nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string3 = "a507307a4b6e0f6f00e8a3f3330204c124fa5a69cfc03ffd89235c7e4b77f25d" nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string4 = "EDBAAABC-1214-41C0-8EEE-B61056DE37ED" nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string5 = "logangoins/Stifle" nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string6 = /Stifle\.exe\sadd\s\/object\:/ nocase ascii wide
        // Description: .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // Reference: https://github.com/logangoins/Stifle
        $string7 = /Stifle\.exe\sclear\s/ nocase ascii wide

    condition:
        any of them
}
