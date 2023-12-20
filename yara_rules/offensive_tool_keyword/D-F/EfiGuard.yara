rule EfiGuard
{
    meta:
        description = "Detection patterns for the tool 'EfiGuard' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EfiGuard"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string1 = /EFIGUARD_BACKDOOR_VARIABLE_NAME/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string2 = /roodkcaBdrauGifE/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string3 = /Protocol\/EfiGuard\.h/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string4 = /\\EfiGuardDxe\.h/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string5 = /\/UefiShell\.iso/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string6 = /\\UefiShell\.iso/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string7 = /\sUefiShell\.iso/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string8 = /\\EfiGuardDxe\.c/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string9 = /\/EfiGuardDxe\.c/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string10 = /\/EfiDSEFix\.exe/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string11 = /\\EfiDSEFix\.exe/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string12 = /EfiDSEFix\.exe\s/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string13 = /\/EfiDSEFix\.cpp/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string14 = /\\EfiDSEFix\.cpp/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string15 = /\sEfiDSEFix\.cpp/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string16 = /\\EfiGuard\.sln/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string17 = /\/EfiGuard\.sln/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string18 = /\\EfiGuardDxe\\X64\\/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string19 = /D7484EBA\-6357\-4D81\-B355\-066E28D5DF72/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string20 = /0E4BAB8F\-E6E0\-47A8\-8E99\-8D451839967E/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string21 = /B2924789\-9912\-4B6F\-8F7B\-53240AC3BA0E/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string22 = /EfiGuard\-v1\.4\.zip/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string23 = /\\Boot\\EfiGuardDxe\.efi/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string24 = /EfiGuard\-v1\.3\.zip/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string25 = /EfiGuard\-v1\.2\.zip/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string26 = /EfiGuard\-v1\.1\.zip/ nocase ascii wide
        // Description: EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // Reference: https://github.com/Mattiwatti/EfiGuard
        $string27 = /EfiGuard\-v1\.5\.zip/ nocase ascii wide

    condition:
        any of them
}
