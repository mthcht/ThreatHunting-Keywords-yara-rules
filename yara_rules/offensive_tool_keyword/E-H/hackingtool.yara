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
        $string1 = /\/hackingtool\.git/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string2 = /anonsurf\.py/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string3 = /exploit_frameworks\.py/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string4 = /hackingtool\.py/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string5 = /information_gathering_tools\.py/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string6 = /payload_creator\.py/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string7 = /phising_attack\.py/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string8 = /post_exploitation\.py/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string9 = /wireless_attack_tools\.py/ nocase ascii wide
        // Description: ALL IN ONE Hacking Tool For Hackers
        // Reference: https://github.com/Z4nzu/hackingtool
        $string10 = /Z4nzu\/hackingtool/ nocase ascii wide

    condition:
        any of them
}
