rule fiddler
{
    meta:
        description = "Detection patterns for the tool 'fiddler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fiddler"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: fiddler - capture https requests
        // Reference: https://www.telerik.com/
        $string1 = /\/download\/fiddler\/fiddler\-everywhere\-windows/ nocase ascii wide
        // Description: fiddler - capture https requests
        // Reference: https://www.telerik.com/
        $string2 = /\/Fiddler\sEverywhere\s.{0,1000}\..{0,1000}\..{0,1000}\.exe/ nocase ascii wide
        // Description: fiddler - capture https requests
        // Reference: https://www.telerik.com/
        $string3 = /\\Fiddler\sEverywhere\s.{0,1000}\..{0,1000}\..{0,1000}\.exe/ nocase ascii wide
        // Description: fiddler - capture https requests
        // Reference: https://www.telerik.com/
        $string4 = /https\:\/\/www\.telerik\.com\/download\/fiddler\// nocase ascii wide

    condition:
        any of them
}
