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
        $string1 = /.{0,1000}\/ThisIsNotRat\.git.{0,1000}/ nocase ascii wide
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string2 = /.{0,1000}\/tinar\.py.{0,1000}/ nocase ascii wide
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string3 = /.{0,1000}python\stinar\.py.{0,1000}/ nocase ascii wide
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string4 = /.{0,1000}RealBey\/ThisIsNotRat.{0,1000}/ nocase ascii wide
        // Description: control windows computeur from telegram
        // Reference: https://github.com/RealBey/ThisIsNotRat
        $string5 = /.{0,1000}ThisIsNotRat\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
