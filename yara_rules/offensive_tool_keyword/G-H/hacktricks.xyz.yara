rule hacktricks_xyz
{
    meta:
        description = "Detection patterns for the tool 'hacktricks.xyz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hacktricks.xyz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: site often consulted by pentester
        // Reference: https://hacktricks.xyz
        $string1 = /book\.hacktricks\.xyz\// nocase ascii wide

    condition:
        any of them
}
