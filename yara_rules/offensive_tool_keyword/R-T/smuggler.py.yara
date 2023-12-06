rule smuggler_py
{
    meta:
        description = "Detection patterns for the tool 'smuggler.py' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smuggler.py"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HTML Smuggling Generator
        // Reference: https://github.com/infosecn1nja/red-team-scripts/blob/main/smuggler.py
        $string1 = /\ssmuggler\.py/ nocase ascii wide
        // Description: HTML Smuggling Generator
        // Reference: https://github.com/infosecn1nja/red-team-scripts/blob/main/smuggler.py
        $string2 = /\/smuggler\.py/ nocase ascii wide
        // Description: HTML Smuggling Generator
        // Reference: https://github.com/infosecn1nja/red-team-scripts/blob/main/smuggler.py
        $string3 = /\\smuggler\.py/ nocase ascii wide

    condition:
        any of them
}
