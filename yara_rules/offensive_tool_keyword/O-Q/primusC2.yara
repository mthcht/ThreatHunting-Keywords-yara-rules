rule primusC2
{
    meta:
        description = "Detection patterns for the tool 'primusC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "primusC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string1 = /.{0,1000}\/C2\/server\.py.{0,1000}/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string2 = /.{0,1000}\/PrimusC2.{0,1000}/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string3 = /.{0,1000}\/PrimusC2\.git.{0,1000}/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string4 = /.{0,1000}:8999\/Payloads\/.{0,1000}/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string5 = /.{0,1000}127\.0\.0\.1:4567.{0,1000}/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string6 = /.{0,1000}localhost:4567.{0,1000}/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string7 = /.{0,1000}PrimusC2\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string8 = /.{0,1000}SELECT\sdisplayName\sFROM\sAntiVirusProduct.{0,1000}/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string9 = /.{0,1000}ssh\s\-N\s\-R\s4567:localhost:.{0,1000}root.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
