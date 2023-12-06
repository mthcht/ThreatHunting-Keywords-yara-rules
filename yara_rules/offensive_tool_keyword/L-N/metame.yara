rule metame
{
    meta:
        description = "Detection patterns for the tool 'metame' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metame"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: metame is a metamorphic code engine for arbitrary executables
        // Reference: https://github.com/a0rtega/metame
        $string1 = /a0rtega\/metame/ nocase ascii wide
        // Description: metame is a metamorphic code engine for arbitrary executables
        // Reference: https://github.com/a0rtega/metame
        $string2 = /import\smetame/ nocase ascii wide
        // Description: metame is a metamorphic code engine for arbitrary executables
        // Reference: https://github.com/a0rtega/metame
        $string3 = /metame\s\-i\s.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
