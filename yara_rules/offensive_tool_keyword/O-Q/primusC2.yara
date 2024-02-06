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
        $string1 = /\/C2\/server\.py/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string2 = /\/PrimusC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string3 = /\/PrimusC2\.git/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string4 = /\:8999\/Payloads\// nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string5 = /127\.0\.0\.1\:4567/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string6 = /localhost\:4567/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string7 = /PrimusC2\-main\.zip/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string8 = /SELECT\sdisplayName\sFROM\sAntiVirusProduct/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/Primusinterp/PrimusC2
        $string9 = /ssh\s\-N\s\-R\s4567\:localhost\:.{0,1000}root/ nocase ascii wide

    condition:
        any of them
}
