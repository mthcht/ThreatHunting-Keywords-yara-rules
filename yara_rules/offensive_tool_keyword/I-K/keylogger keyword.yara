rule keylogger_keyword
{
    meta:
        description = "Detection patterns for the tool 'keylogger keyword' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "keylogger keyword"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: keylogger keyword. could be related to keylooger tools 
        // Reference: N/A
        $string1 = "Keylogger" nocase ascii wide

    condition:
        any of them
}
