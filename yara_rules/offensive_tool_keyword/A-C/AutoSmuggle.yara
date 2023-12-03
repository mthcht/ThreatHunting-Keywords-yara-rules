rule AutoSmuggle
{
    meta:
        description = "Detection patterns for the tool 'AutoSmuggle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSmuggle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string1 = /.{0,1000}\/AutoSmuggle\.git.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string2 = /.{0,1000}\[.{0,1000}\]\sSmuggling\sin\sHTML.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string3 = /.{0,1000}\[.{0,1000}\]\sSmuggling\sin\sSVG.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string4 = /.{0,1000}\\AutoSmuggle\\.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string5 = /.{0,1000}57A893C7\-7527\-4B55\-B4E9\-D644BBDA89D1.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string6 = /.{0,1000}AutoSmuggle\.csproj.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string7 = /.{0,1000}AutoSmuggle\.exe.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string8 = /.{0,1000}AutoSmuggle\.sln.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string9 = /.{0,1000}AutoSmuggle\-master.{0,1000}/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string10 = /.{0,1000}surajpkhetani\/AutoSmuggle.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
