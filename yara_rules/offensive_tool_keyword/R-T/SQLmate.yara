rule SQLmate
{
    meta:
        description = "Detection patterns for the tool 'SQLmate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SQLmate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A friend of SQLmap which will do what you always expected from SQLmap.
        // Reference: https://github.com/s0md3v/sqlmate
        $string1 = /SQLmate/ nocase ascii wide

    condition:
        any of them
}
