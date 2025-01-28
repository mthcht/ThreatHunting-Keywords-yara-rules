rule scanless
{
    meta:
        description = "Detection patterns for the tool 'scanless' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scanless"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a Python 3 command-line utility and library for using websites that can perform port scans on your behalf
        // Reference: https://github.com/vesche/scanless
        $string1 = "scanless" nocase ascii wide

    condition:
        any of them
}
