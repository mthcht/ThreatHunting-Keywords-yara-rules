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
        $string16 = "81E60DC6-694E-4F51-88FA-6F481B9A4208" nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string17 = "81E60DC6-694E-4F51-88FA-6F481B9A4208" nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string18 = /bin2mac\.py\s.{0,100}\.bin/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string19 = /PatchingAPI\.exe/ nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string20 = "SaadAhla/UnhookingPatch" nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string21 = "TheD1rkMtr/UnhookingPatch" nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/SaadAhla/UnhookingPatch
        $string22 = "UnhookingPatch-main" nocase ascii wide
        // Description: Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // Reference: https://github.com/TheD1rkMtr/UnhookingPatch
        $string23 = "UnhookingPatch-main" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
