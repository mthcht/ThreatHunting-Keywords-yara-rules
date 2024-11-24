rule RemCom
{
    meta:
        description = "Detection patterns for the tool 'RemCom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemCom"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string1 = /\s\\\\\\\\localhost\s\/user\:Username\s\/pwd\:Password\s\s\\\\"C\:\\\\InstallMe\.bat/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string2 = /\sRemCom\.exe/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string3 = /\sRemComSvc\.exe/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string4 = /\sRemComSvc\.h/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string5 = /\.\\RemComSvc\\/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string6 = /\/RemCom\.exe/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string7 = /\/RemCom\.git/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string8 = /\/RemComSvc\.exe/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string9 = /\[\stalha\.tariq\@gmail\.com\s\]/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string10 = /\\RemCom\.cpp/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string11 = /\\RemCom\.exe/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string12 = /\\RemCom\.pdb/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string13 = /\\RemCom\.vcxproj/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string14 = /\\RemCom\-master\\/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string15 = /\\RemComSvc\.exe/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string16 = /\\RemComSvc\\/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string17 = /\\Remote\sCommand\sExecutor\.sln/ nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string18 = "0d8f28ea01d3866ad7ee4abbdc5bdfd83d41702dcf029584ef30cb0055be8538" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string19 = "29548EB7-5E44-21F9-5C82-15DDDC80449A" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string20 = "8CC59FFA-00E0-0AEA-59E8-E780672C3CB3" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string21 = "C7038612-8183-67A7-8A9C-1379C2674156" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string22 = "define RemComSVCEXE" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string23 = "eee20962a1056f525bbe1c99c656794511697e510221522e7d62efd943457190" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string24 = "kavika13/RemCom" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string25 = "RemCom - Win32 Debug" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string26 = "RemCom - Win32 Release" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string27 = "RemComSvc - Win32 Debug" nocase ascii wide
        // Description: Remote Command Executor: A OSS replacement for PsExec and RunAs
        // Reference: https://github.com/kavika13/RemCom
        $string28 = "RemComSvc - Win32 Release" nocase ascii wide
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
