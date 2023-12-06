rule BYOVD_kill_av_edr
{
    meta:
        description = "Detection patterns for the tool 'BYOVD_kill_av_edr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BYOVD_kill_av_edr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BYOD to kill AV/EDR
        // Reference: https://github.com/infosecn1nja/red-team-scripts/blob/main/BYOVD_kill_av_edr.c
        $string1 = /\\\\\\\\\.\\\\aswSP_Avar/ nocase ascii wide
        // Description: BYOD to kill AV/EDR
        // Reference: https://github.com/infosecn1nja/red-team-scripts/blob/main/BYOVD_kill_av_edr.c
        $string2 = /BYOVD_kill_av_edr\./ nocase ascii wide

    condition:
        any of them
}
