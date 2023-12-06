rule archerysec
{
    meta:
        description = "Detection patterns for the tool 'archerysec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "archerysec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Archery is an opensource vulnerability assessment and management tool which helps developers and pentesters to perform scans and manage vulnerabilities. Archery uses popular opensource tools to perform comprehensive scanning for web application and network. It also performs web application dynamic authenticated scanning and covers the whole applications by using selenium. The developers can also utilize the tool for implementation of their DevOps CI/CD environment.
        // Reference: https://github.com/archerysec/archerysec
        $string1 = /archerysec/ nocase ascii wide

    condition:
        any of them
}
