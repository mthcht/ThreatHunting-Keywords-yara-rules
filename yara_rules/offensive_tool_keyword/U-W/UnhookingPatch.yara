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
        $string1 = /.{0,1000}\/PatchingAPI\.cpp.{0,1000}/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string2 = /.{0,1000}\/PatchingAPI\.exe.{0,1000}/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string3 = /.{0,1000}\/UnhookingPatch\.git.{0,1000}/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string4 = /.{0,1000}\\PatchingAPI\.cpp.{0,1000}/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string5 = /.{0,1000}\\PatchingAPI\.exe.{0,1000}/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string6 = /.{0,1000}81E60DC6\-694E\-4F51\-88FA\-6F481B9A4208.{0,1000}/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string7 = /.{0,1000}TheD1rkMtr\/UnhookingPatch.{0,1000}/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string8 = /.{0,1000}UnhookingPatch\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
