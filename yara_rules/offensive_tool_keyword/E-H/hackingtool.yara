rule hackingtool
{
    meta:
        description = "Detection patterns for the tool 'hackingtool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hackingtool"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string1 = /.{0,1000}\/hackingtool\.git.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string2 = /.{0,1000}anonsurf\.py.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string3 = /.{0,1000}exploit_frameworks\.py.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string4 = /.{0,1000}hackingtool\.py.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string5 = /.{0,1000}information_gathering_tools\.py.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string6 = /.{0,1000}payload_creator\.py.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string7 = /.{0,1000}phising_attack\.py.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string8 = /.{0,1000}post_exploitation\.py.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string9 = /.{0,1000}wireless_attack_tools\.py.{0,1000}/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string10 = /.{0,1000}Z4nzu\/hackingtool.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
