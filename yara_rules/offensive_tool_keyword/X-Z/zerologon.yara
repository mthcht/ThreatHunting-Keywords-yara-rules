rule zerologon
{
    meta:
        description = "Detection patterns for the tool 'zerologon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zerologon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Zerologon CVE exploitation
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = /\.py\s\-no\-pass\s\-just\-dc\s/ nocase ascii wide
        // Description: Zerologon CVE exploitation
        // Reference: https://github.com/michaelpoznecki/zerologon
        $string2 = /\/nrpc\.py/ nocase ascii wide
        // Description: Zerologon CVE exploitation
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = /\\zero\.exe\s.{0,1000}ProgramData/ nocase ascii wide
        // Description: Zerologon CVE exploitation
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string4 = /cve\-2020\-1472\-exploit\.py/ nocase ascii wide

    condition:
        any of them
}
