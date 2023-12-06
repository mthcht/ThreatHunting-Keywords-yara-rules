rule ThisIsNotRat
{
    meta:
        description = "Detection patterns for the tool 'ThisIsNotRat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThisIsNotRat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string1 = /\/ThisIsNotRat\.git/ nocase ascii wide
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string2 = /\/tinar\.py/ nocase ascii wide
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string3 = /python\stinar\.py/ nocase ascii wide
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string4 = /RealBey\/ThisIsNotRat/ nocase ascii wide
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string5 = /ThisIsNotRat\-main/ nocase ascii wide

    condition:
        any of them
}
