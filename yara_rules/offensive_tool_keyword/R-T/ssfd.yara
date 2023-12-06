rule ssfd
{
    meta:
        description = "Detection patterns for the tool 'ssfd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssfd"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: sets up a communication channel possibly for command and control (C2) or exfiltration purposes
        // Reference: https://github.com/securesocketfunneling/ssf
        $string1 = /ssf\.exe\s\-D\s.{0,1000}\s\-p\s.{0,1000}\s127\.0\.0\.1/ nocase ascii wide
        // Description: sets up a communication channel possibly for command and control (C2) or exfiltration purposes
        // Reference: https://github.com/securesocketfunneling/ssf
        $string2 = /ssfd\.exe\s\-p\s/ nocase ascii wide

    condition:
        any of them
}
