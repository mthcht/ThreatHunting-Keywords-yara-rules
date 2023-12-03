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
        $string1 = /.{0,1000}\s\-f\s.{0,1000}\.bin\s\-e\sAMSI.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string2 = /.{0,1000}\s\-f\s.{0,1000}\.bin\s\-e\sDefender.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string3 = /.{0,1000}\s\-Scan\s\-ScanType\s3\s\-File\s.{0,1000}\s\-DisableRemediation\s\-Trace\s\-Level\s0x10.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string4 = /.{0,1000}\/ThreatCheck\.git.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string5 = /.{0,1000}\\Blackout\.sys.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string6 = /.{0,1000}\\NimBlackout.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string7 = /.{0,1000}C:\\Temp\\file\.exe.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string8 = /.{0,1000}NimBlackout.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string9 = /.{0,1000}NimBlackout\..{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string10 = /.{0,1000}NimBlackout\-main.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string11 = /.{0,1000}rasta\-mouse\/ThreatCheck.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string12 = /.{0,1000}ThreatCheck\.csproj.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string13 = /.{0,1000}ThreatCheck\.csproj.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string14 = /.{0,1000}ThreatCheck\.exe.{0,1000}/ nocase ascii wide
        // Description: Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // Reference: https://github.com/rasta-mouse/ThreatCheck
        $string15 = /.{0,1000}ThreatCheck\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
