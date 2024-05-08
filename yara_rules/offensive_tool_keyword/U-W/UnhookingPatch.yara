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
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string1 = /\sbin2mac\.py/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string2 = /\/PatchingAPI\.cpp/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string3 = /\/PatchingAPI\.exe/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string4 = /\/UnhookingPatch\.git/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string5 = /\/UnhookingPatch\.git/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string6 = /\[\-\]\sNtAllocateVirtualMemory\sHooked/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string7 = /\[\-\]\sNtProtectVirtualMemory\sHooked/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string8 = /\[\-\]\sNtWaitForSingleObject\sHooked/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string9 = /\[\+\]\sNtAllocateVirtualMemory\sNot\sHooked/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string10 = /\[\+\]\sNtProtectVirtualMemory\sNot\sHooked/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string11 = /\[\+\]\sNtWaitForSingleObject\sNot\sHooked/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string12 = /\\PatchingAPI\.cpp/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string13 = /\\PatchingAPI\.cpp/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string14 = /\\PatchingAPI\.exe/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string15 = /\\UnhookingPatch\\bin2mac\.py/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string16 = /81E60DC6\-694E\-4F51\-88FA\-6F481B9A4208/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string17 = /81E60DC6\-694E\-4F51\-88FA\-6F481B9A4208/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string18 = /bin2mac\.py\s.{0,1000}\.bin/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string19 = /PatchingAPI\.exe/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string20 = /SaadAhla\/UnhookingPatch/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string21 = /TheD1rkMtr\/UnhookingPatch/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string22 = /UnhookingPatch\-main/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string23 = /UnhookingPatch\-main/ nocase ascii wide

    condition:
        any of them
}
