rule themebleed
{
    meta:
        description = "Detection patterns for the tool 'themebleed' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "themebleed"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Proof-of-Concept for CVE-2023-38146
        // Reference: https://github.com/gabe-k/themebleed
        $string1 = /\/ThemeBleed\.exe/ nocase ascii wide
        // Description: Proof-of-Concept for CVE-2023-38146
        // Reference: https://github.com/gabe-k/themebleed
        $string2 = /\\ThemeBleed\.exe\s/ nocase ascii wide
        // Description: Proof-of-Concept for CVE-2023-38146
        // Reference: https://github.com/gabe-k/themebleed
        $string3 = /\\ThemeBleed\.sln/ nocase ascii wide
        // Description: Proof-of-Concept for CVE-2023-38146
        // Reference: https://github.com/gabe-k/themebleed
        $string4 = /1BACEDDC\-CD87\-41DC\-948C\-1C12F960BECB/ nocase ascii wide
        // Description: Proof-of-Concept for CVE-2023-38146
        // Reference: https://github.com/gabe-k/themebleed
        $string5 = /ThemeBleed\.exe\s\s/ nocase ascii wide

    condition:
        any of them
}
