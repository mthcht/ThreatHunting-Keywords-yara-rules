rule NativeBypassCredGuard
{
    meta:
        description = "Detection patterns for the tool 'NativeBypassCredGuard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NativeBypassCredGuard"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string1 = /\/NativeBypassCredGuard\.git/ nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string2 = /\[\+\]\sEnable\sSeDebugPrivilege\:\s\\tOK/ nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string3 = /\\NativeBypassCredGuard\.sln/ nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string4 = /\\NativeBypassCredGuard_C\+\+/ nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string5 = /\\NativeBypassCredGuard\-main/ nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string6 = "0614ec0ae3a38dd774d2e03dfeb05bad8e2c573f1943ab951c6129825bde4df8" nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string7 = "1d294d6fcae8b9d57d60166f102fd91d63ad88def2ab80eadcac22750f6f3c47" nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string8 = "28bba6f4d8a170a77e383fe09fcc3d5258496fb45b0c226891cc51f8b96ef489" nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string9 = "c4d31433-5017-4b5e-956b-8a540520986c" nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string10 = "E383DFEA-EC22-4667-9434-3F2591A03740" nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string11 = /NativeBypassCredGuard\.exe/ nocase ascii wide
        // Description: Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // Reference: https://github.com/ricardojoserf/NativeBypassCredGuard
        $string12 = "ricardojoserf/NativeBypassCredGuard" nocase ascii wide

    condition:
        any of them
}
