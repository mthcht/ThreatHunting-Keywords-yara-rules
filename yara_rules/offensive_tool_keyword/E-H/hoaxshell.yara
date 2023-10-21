rule hoaxshell
{
    meta:
        description = "Detection patterns for the tool 'hoaxshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hoaxshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string1 = /\.\/hoaxshell/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string2 = /\/hoaxshell/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string3 = /\/http_payload\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string4 = /\/https_payload\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string5 = /hoaxshell\.py/ nocase ascii wide

    condition:
        any of them
}