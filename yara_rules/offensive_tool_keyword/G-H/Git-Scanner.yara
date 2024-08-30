rule Git_Scanner
{
    meta:
        description = "Detection patterns for the tool 'Git-Scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Git-Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for bug hunting or pentesting for targeting websites that have open .git repositories available in public
        // Reference: https://github.com/HightechSec/git-scanner
        $string1 = /Git\-Scanner/ nocase ascii wide

    condition:
        any of them
}
