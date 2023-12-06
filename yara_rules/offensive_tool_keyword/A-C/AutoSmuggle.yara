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
        $string1 = /\/AutoSmuggle\.git/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string2 = /\[.{0,1000}\]\sSmuggling\sin\sHTML/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string3 = /\[.{0,1000}\]\sSmuggling\sin\sSVG/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string4 = /\\AutoSmuggle\\.{0,1000}\.cs/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string5 = /57A893C7\-7527\-4B55\-B4E9\-D644BBDA89D1/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string6 = /AutoSmuggle\.csproj/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string7 = /AutoSmuggle\.exe/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string8 = /AutoSmuggle\.sln/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string9 = /AutoSmuggle\-master/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string10 = /surajpkhetani\/AutoSmuggle/ nocase ascii wide

    condition:
        any of them
}
