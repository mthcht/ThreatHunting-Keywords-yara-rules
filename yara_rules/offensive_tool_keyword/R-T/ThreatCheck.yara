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
        $string7 = /C\:\\Temp\\file\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string8 = /NimBlackout.{0,1000}\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string9 = /NimBlackout\./ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string10 = /NimBlackout\-main/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string11 = /rasta\-mouse\/ThreatCheck/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string12 = /ThreatCheck\.csproj/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string13 = /ThreatCheck\.csproj/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string14 = /ThreatCheck\.exe/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string15 = /ThreatCheck\-master/ nocase ascii wide

    condition:
        any of them
}
