rule DumpCreds
{
    meta:
        description = "Detection patterns for the tool 'DumpCreds' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpCreds"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumpcreds is a tool that may be used to extract various credentials from running processes. I just take a look at mimipenguin(https://github.com/huntergregal/mimipenguin) and tried to improve it a bit
        // Reference: https://github.com/ponypot/dumpcreds
        $string1 = /DumpCreds/ nocase ascii wide

    condition:
        any of them
}
