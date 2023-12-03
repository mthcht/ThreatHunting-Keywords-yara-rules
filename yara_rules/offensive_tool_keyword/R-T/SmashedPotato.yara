rule SmashedPotato
{
    meta:
        description = "Detection patterns for the tool 'SmashedPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SmashedPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A modification of @breenmachine original Hot Potato Priv Esc Exploit
        // Reference: https://github.com/Cn33liz/SmashedPotato
        $string1 = /.{0,1000}SmashedPotato\.cs.{0,1000}/ nocase ascii wide
        // Description: A modification of @breenmachine original Hot Potato Priv Esc Exploit
        // Reference: https://github.com/Cn33liz/SmashedPotato
        $string2 = /.{0,1000}SmashedPotato\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
