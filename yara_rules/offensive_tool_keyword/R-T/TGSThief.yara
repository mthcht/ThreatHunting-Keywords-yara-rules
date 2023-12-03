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
        $string1 = /.{0,1000}\/releases\/download\/.{0,1000}\/abc\.exe.{0,1000}/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string2 = /.{0,1000}\/TGSThief\.git.{0,1000}/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string3 = /.{0,1000}\/TGSThief\/.{0,1000}/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string4 = /.{0,1000}\\TGSThief\\.{0,1000}/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string5 = /.{0,1000}MzHmO\/TGSThief.{0,1000}/ nocase ascii wide
        // Description: get the TGS of a user whose logon session is just present on the computer
        // Reference: https://github.com/MzHmO/TGSThief
        $string6 = /.{0,1000}TGSThief\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
