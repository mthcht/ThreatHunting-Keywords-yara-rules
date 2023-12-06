rule crunch
{
    meta:
        description = "Detection patterns for the tool 'crunch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crunch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generate a dictionary file containing words with a minimum and maximum length
        // Reference: https://sourceforge.net/projects/crunch-wordlist/
        $string1 = /\/crunch\-wordlist\// nocase ascii wide
        // Description: Generate a dictionary file containing words with a minimum and maximum length
        // Reference: https://sourceforge.net/projects/crunch-wordlist/
        $string2 = /apt\sinstall\scrunch/ nocase ascii wide
        // Description: Generate a dictionary file containing words with a minimum and maximum length
        // Reference: https://sourceforge.net/projects/crunch-wordlist/
        $string3 = /crunch\s.{0,1000}\s\-o\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}
