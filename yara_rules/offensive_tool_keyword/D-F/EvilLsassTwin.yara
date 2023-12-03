rule EvilLsassTwin
{
    meta:
        description = "Detection patterns for the tool 'EvilLsassTwin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilLsassTwin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string1 = /.{0,1000}\sEvilTwinServer\s.{0,1000}/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string2 = /.{0,1000}\/EvilLsassTwin\/.{0,1000}/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string3 = /.{0,1000}\/EvilTwinServer.{0,1000}/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string4 = /.{0,1000}EvilLsassTwin\.exe.{0,1000}/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string5 = /.{0,1000}EvilLsassTwin\.nim.{0,1000}/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string6 = /.{0,1000}EvilTwin\.dmp.{0,1000}/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string7 = /.{0,1000}EvilTwinServer\.nim.{0,1000}/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string8 = /.{0,1000}Lsass\sDump\sFile\sCreated.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
