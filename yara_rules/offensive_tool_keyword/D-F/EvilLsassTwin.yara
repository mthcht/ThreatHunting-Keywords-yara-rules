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
        $string1 = /\sEvilTwinServer\s/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string2 = /\/EvilLsassTwin\// nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string3 = /\/EvilTwinServer/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string4 = /EvilLsassTwin\.exe/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string5 = /EvilLsassTwin\.nim/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string6 = /EvilTwin\.dmp/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string7 = /EvilTwinServer\.nim/ nocase ascii wide
        // Description: attempt to duplicate open handles to LSASS. If this fails it will obtain a handle to LSASS through the NtGetNextProcess function instead of OpenProcess/NtOpenProcess.
        // Reference: https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin
        $string8 = /Lsass\sDump\sFile\sCreated/ nocase ascii wide

    condition:
        any of them
}
