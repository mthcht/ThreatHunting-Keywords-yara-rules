rule GlobalUnProtect
{
    meta:
        description = "Detection patterns for the tool 'GlobalUnProtect' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GlobalUnProtect"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt GlobalProtect configuration and cookie files.
        // Reference: https://github.com/rotarydrone/GlobalUnProtect
        $string1 = /\/GlobalUnProtect\.git/ nocase ascii wide
        // Description: Decrypt GlobalProtect configuration and cookie files.
        // Reference: https://github.com/rotarydrone/GlobalUnProtect
        $string2 = /\\GPUnprotect\.zip/ nocase ascii wide
        // Description: Decrypt GlobalProtect configuration and cookie files.
        // Reference: https://github.com/rotarydrone/GlobalUnProtect
        $string3 = /376890088b7c004896fa764dc8148944e9dcee1017c481e246b892520f96aa6e/ nocase ascii wide
        // Description: Decrypt GlobalProtect configuration and cookie files.
        // Reference: https://github.com/rotarydrone/GlobalUnProtect
        $string4 = /E9172085\-1595\-4E98\-ABF8\-E890D2489BB5/ nocase ascii wide
        // Description: Decrypt GlobalProtect configuration and cookie files.
        // Reference: https://github.com/rotarydrone/GlobalUnProtect
        $string5 = /GlobalUnProtect\.exe/ nocase ascii wide
        // Description: Decrypt GlobalProtect configuration and cookie files.
        // Reference: https://github.com/rotarydrone/GlobalUnProtect
        $string6 = /rotarydrone\/GlobalUnProtect/ nocase ascii wide

    condition:
        any of them
}
