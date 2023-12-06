rule afrog
{
    meta:
        description = "Detection patterns for the tool 'afrog' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "afrog"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for finding vulnerabilities
        // Reference: https://github.com/zan8in/afrog
        $string1 = /\/afrog\-pocs\// nocase ascii wide
        // Description: A tool for finding vulnerabilities
        // Reference: https://github.com/zan8in/afrog
        $string2 = /afrog\s\-/ nocase ascii wide

    condition:
        any of them
}
