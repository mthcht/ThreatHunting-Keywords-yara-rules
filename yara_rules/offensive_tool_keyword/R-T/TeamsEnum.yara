rule TeamsEnum
{
    meta:
        description = "Detection patterns for the tool 'TeamsEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TeamsEnum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: User Enumeration of Microsoft Teams users via API
        // Reference: https://github.com/sse-secure-systems/TeamsEnum
        $string1 = /\steamsenum\.py/ nocase ascii wide
        // Description: User Enumeration of Microsoft Teams users via API
        // Reference: https://github.com/sse-secure-systems/TeamsEnum
        $string2 = /\/TeamsEnum\.git/ nocase ascii wide
        // Description: User Enumeration of Microsoft Teams users via API
        // Reference: https://github.com/sse-secure-systems/TeamsEnum
        $string3 = /\/teamsenum\.py/ nocase ascii wide
        // Description: User Enumeration of Microsoft Teams users via API
        // Reference: https://github.com/sse-secure-systems/TeamsEnum
        $string4 = /\\teamsenum\.py/ nocase ascii wide
        // Description: User Enumeration of Microsoft Teams users via API
        // Reference: https://github.com/sse-secure-systems/TeamsEnum
        $string5 = "1228965bfca9be58b2370874d794ce293238ef8a7faa1f6c744374300aa8a79d" nocase ascii wide
        // Description: User Enumeration of Microsoft Teams users via API
        // Reference: https://github.com/sse-secure-systems/TeamsEnum
        $string6 = "5df59d3aeb2b438458b5dfe2a8f0bbc15da03a6c222d9cf57aff6df5f682ee31" nocase ascii wide
        // Description: User Enumeration of Microsoft Teams users via API
        // Reference: https://github.com/sse-secure-systems/TeamsEnum
        $string7 = /import\steamsenum\.auth/ nocase ascii wide
        // Description: User Enumeration of Microsoft Teams users via API
        // Reference: https://github.com/sse-secure-systems/TeamsEnum
        $string8 = "sse-secure-systems/TeamsEnum" nocase ascii wide

    condition:
        any of them
}
