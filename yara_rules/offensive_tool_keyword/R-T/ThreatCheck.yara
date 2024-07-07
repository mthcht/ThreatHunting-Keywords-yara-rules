rule ThreatCheck
{
    meta:
        description = "Detection patterns for the tool 'ThreatCheck' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThreatCheck"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string1 = /\s\-f\s.{0,1000}\.bin\s\-e\sAMSI/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string2 = /\s\-f\s.{0,1000}\.bin\s\-e\sDefender/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string3 = /\s\-Scan\s\-ScanType\s3\s\-File\s.{0,1000}\s\-DisableRemediation\s\-Trace\s\-Level\s0x10/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string4 = /\/ThreatCheck\.git/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string5 = /\\Blackout\.sys/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string6 = /\\NimBlackout/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string7 = /3EC9B9A8\-0AFE\-44A7\-8B95\-7F60E750F042/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string8 = /76f677acfe19ca1e1e39c391e4923dc38e1e3f752097c5808c171c1d5228194e/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string9 = /C\:\\Temp\\file\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string10 = /NimBlackout.{0,1000}\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string11 = /NimBlackout\./ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string12 = /NimBlackout\-main/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string13 = /rasta\-mouse\/ThreatCheck/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string14 = /ThreatCheck\.csproj/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string15 = /ThreatCheck\.csproj/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string16 = /ThreatCheck\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string17 = /ThreatCheck\-master/ nocase ascii wide

    condition:
        any of them
}
