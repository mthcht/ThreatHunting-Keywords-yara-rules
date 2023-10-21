rule UnhookingPatch
{
    meta:
        description = "Detection patterns for the tool 'UnhookingPatch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnhookingPatch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string1 = /\/PatchingAPI\.cpp/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string2 = /\/PatchingAPI\.exe/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string3 = /\/UnhookingPatch\.git/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string4 = /\\PatchingAPI\.cpp/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string5 = /\\PatchingAPI\.exe/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string6 = /81E60DC6\-694E\-4F51\-88FA\-6F481B9A4208/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string7 = /TheD1rkMtr\/UnhookingPatch/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string8 = /UnhookingPatch\-main/ nocase ascii wide

    condition:
        any of them
}