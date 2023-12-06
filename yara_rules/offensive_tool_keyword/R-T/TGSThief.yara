rule TGSThief
{
    meta:
        description = "Detection patterns for the tool 'TGSThief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TGSThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string1 = /\/releases\/download\/.{0,1000}\/abc\.exe/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string2 = /\/TGSThief\.git/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string3 = /\/TGSThief\// nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string4 = /\\TGSThief\\/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string5 = /MzHmO\/TGSThief/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string6 = /TGSThief\-main/ nocase ascii wide

    condition:
        any of them
}
