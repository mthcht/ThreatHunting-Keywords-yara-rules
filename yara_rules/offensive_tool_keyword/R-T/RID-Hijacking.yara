rule RID_Hijacking
{
    meta:
        description = "Detection patterns for the tool 'RID-Hijacking' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RID-Hijacking"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string1 = /\srid_hijack\.py/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string2 = /\/rid_hijack\.py/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string3 = /\/RID\-Hijacking\.git/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string4 = /\[\+\]\sElevated\sto\sSYSTEM\sprivileges/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string5 = /\\persistence\\elevated\\rid_hijack/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string6 = /\\rid_hijack\.py/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string7 = /\\rid_hijack\.rb/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string8 = /\\RID\-Hijacking\\/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string9 = /\\RID\-Hijacking\-master/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string10 = /233d785a077c50ad57de73da20e8696258a99edbc6961b92530dac81aede0bcb/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string11 = /9f1853b2b8ee03b428bfcad0502959b2a00761471599e3db4c86ab9550df9b69/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string12 = /a18ad37ac14721d1aab3478bdb2d5534b5035dfb9b3fa5d0945f4d5252936e51/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string13 = /e75d251f639cc70aba21e621c2710dc3ee9dc15d1a677a157f83c14e9aff5f8e/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string14 = /f236aee384d7a0fab7fc186454ee6adb83b756843ecf75ec14b3df826a66ff1d/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string15 = /Invoke\-RIDHijacking/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string16 = /invoke\-ridhijacking\.py/ nocase ascii wide
        // Description: Windows RID Hijacking persistence technique
        // Reference: https://github.com/r4wd3r/RID-Hijacking
        $string17 = /r4wd3r\/RID\-Hijacking/ nocase ascii wide
        // Description: RID Hijacking Proof of Concept script by Kevin Joyce
        // Reference: https://github.com/STEALTHbits/RIDHijackingProofofConceptKJ
        $string18 = /RIDHIJACK\.ps1/ nocase ascii wide

    condition:
        any of them
}
