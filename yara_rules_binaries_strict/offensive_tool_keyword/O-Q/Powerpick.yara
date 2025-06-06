rule Powerpick
{
    meta:
        description = "Detection patterns for the tool 'Powerpick' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powerpick"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string1 = /\/DLLEnc\.ps1/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string2 = /\/PowerPick\.exe/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string3 = /\/PSInject\.ps1/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string4 = /\/ReflectivePick_x64\.dll/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string5 = /\/ReflectivePick_x86\.dll/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string6 = /\/sharppick\.exe/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string7 = /\\DLLEnc\.ps1/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string8 = /\\PowerPick\.exe/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string9 = /\\PowerPick\\SharpPick\\/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string10 = /\\PowerTools\\PowerPick\\/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string11 = /\\PSInject\.ps1/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string12 = /\\ReflectivePick\.cpp/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string13 = /\\ReflectivePick_x64\.dll/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string14 = /\\ReflectivePick_x86\.dll/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string15 = /\\sharppick\.exe/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string16 = "_REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string17 = "5ED2F78E-8538-4C87-BCED-E19E9DAD879C" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string18 = "780d27ade8e534dc6affd96eeeea3e5ca9bf3e8fc3cc3257597b90f855dd583c" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string19 = "7C3D26E5-0A61-479A-AFAC-D34F2659F301" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string20 = "AAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gR" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string21 = /AAAAAAAAAAA6AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAC4Fx3y\/HZzofx2c6H8dnOh4iTgof52c6GTANih\+XZzoefr7aHvdnOh9Q7gofl2c6H8dnKhoHZzoefr2aGVdnO/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string22 = /AAAAAAAAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACp8yO07ZJN5\+2STeftkk3n88De5\+\+STeeC5Obn6JJN5\/YP5ufFkk3n9g\/n54ySTef2D9Pn55JN5\+Tq3ufokk3/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string23 = "afed646dee07893f5be9103606c2eeda2545e75b59b03e0a1e2fc42940e09d43" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string24 = "c7895e40feadeded96faf3a9c5fb0423bc16c5005aa419771c70849e9679e807" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string25 = /Console\.Write\(\\"InexorablePoSH/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string26 = /import\-module\spsinject\.ps1/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string27 = /inexorableposh\.exe/ nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string28 = "Invoke-PSInject" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string29 = "powerpick Get-" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string30 = "PowerShellRunner_dll_len" nocase ascii wide
        // Description: allowing the execution of Powershell functionality without the use of Powershell.exe
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string31 = /sharppick\.exe\s/ nocase ascii wide
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
