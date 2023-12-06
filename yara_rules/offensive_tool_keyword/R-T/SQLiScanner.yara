rule SQLiScanner
{
    meta:
        description = "Detection patterns for the tool 'SQLiScanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SQLiScanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatic SQL injection with Charles and sqlmapapi
        // Reference: https://github.com/0xbug/SQLiScanner
        $string1 = /SQLiScanner/ nocase ascii wide

    condition:
        any of them
}
