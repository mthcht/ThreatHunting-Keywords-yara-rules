rule PWCrack
{
    meta:
        description = "Detection patterns for the tool 'PWCrack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWCrack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: cracking tool for multiple hash type
        // Reference: https://github.com/L-codes/pwcrack-framework
        $string1 = /PWCrack/ nocase ascii wide

    condition:
        any of them
}