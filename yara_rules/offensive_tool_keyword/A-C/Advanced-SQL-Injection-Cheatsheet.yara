rule Advanced_SQL_Injection_Cheatsheet
{
    meta:
        description = "Detection patterns for the tool 'Advanced-SQL-Injection-Cheatsheet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Advanced-SQL-Injection-Cheatsheet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A cheat sheet that contains advanced queries for SQL Injection of all types.
        // Reference: https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet
        $string1 = /Advanced\-SQL\-Injection\-Cheatsheet/ nocase ascii wide

    condition:
        any of them
}
