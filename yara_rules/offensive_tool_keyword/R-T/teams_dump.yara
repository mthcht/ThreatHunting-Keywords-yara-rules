rule teams_dump
{
    meta:
        description = "Detection patterns for the tool 'teams_dump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teams_dump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC for dumping and decrypting cookies in the latest version of Microsoft Teams
        // Reference: https://github.com/byinarie/teams_dump
        $string1 = /\steams_dump\.py/ nocase ascii wide
        // Description: PoC for dumping and decrypting cookies in the latest version of Microsoft Teams
        // Reference: https://github.com/byinarie/teams_dump
        $string2 = /\/teams_dump\.git/ nocase ascii wide
        // Description: PoC for dumping and decrypting cookies in the latest version of Microsoft Teams
        // Reference: https://github.com/byinarie/teams_dump
        $string3 = /\/teams_dump\.py/ nocase ascii wide
        // Description: PoC for dumping and decrypting cookies in the latest version of Microsoft Teams
        // Reference: https://github.com/byinarie/teams_dump
        $string4 = /\\teams_dump\.py/ nocase ascii wide
        // Description: PoC for dumping and decrypting cookies in the latest version of Microsoft Teams
        // Reference: https://github.com/byinarie/teams_dump
        $string5 = /byinarie\/teams_dump/ nocase ascii wide
        // Description: PoC for dumping and decrypting cookies in the latest version of Microsoft Teams
        // Reference: https://github.com/byinarie/teams_dump
        $string6 = /teams_dump\.py\steams/ nocase ascii wide
        // Description: PoC for dumping and decrypting cookies in the latest version of Microsoft Teams
        // Reference: https://github.com/byinarie/teams_dump
        $string7 = /teams_dump\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
