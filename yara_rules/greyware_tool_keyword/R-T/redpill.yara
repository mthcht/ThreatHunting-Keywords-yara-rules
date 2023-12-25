rule redpill
{
    meta:
        description = "Detection patterns for the tool 'redpill' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redpill"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string1 = /\sGet\-AVStatus\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string2 = /\slist\-recycle\-bin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string3 = /\sps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string4 = /\.ps1\s\-sysinfo\sEnum/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string5 = /\/ps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string6 = /\/vbs2exe\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string7 = /\\credentials\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string8 = /\\Get\-AVStatus\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string9 = /\\ksjjhav\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string10 = /\\list\-recycle\-bin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string11 = /\\OutlookEmails\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string12 = /\\ps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string13 = /\\Screenshot\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string14 = /\\Screenshot\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string15 = /\\Temp\\clipboard\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string16 = /\\Temp\\dave\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string17 = /\\Temp\\fsdgss\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string18 = /\\vbs2exe\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string19 = /BATtoEXEconverter\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string20 = /identify_offensive_tools\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string21 = /Mitre\-T1202\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string22 = /Temp\\iprange\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string23 = /vbs2exe\.exe\s/ nocase ascii wide

    condition:
        any of them
}
