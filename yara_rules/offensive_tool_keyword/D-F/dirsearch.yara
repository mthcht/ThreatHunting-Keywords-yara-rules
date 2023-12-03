rule dirsearch
{
    meta:
        description = "Detection patterns for the tool 'dirsearch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirsearch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dirsearch is a mature command-line tool designed to brute force directories and files in webservers.
        // Reference: https://github.com/maurosoria/dirsearch
        $string1 = /.{0,1000}dirsearch.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
