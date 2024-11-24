rule Pspersist
{
    meta:
        description = "Detection patterns for the tool 'Pspersist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pspersist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string1 = /\/PSpersist\.git/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string2 = /\\PSprofile\.exe/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string3 = "436b7f540f534a0ec1337cf82a76cb7727acda423132195f0c81560cdf75c438" nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string4 = "58482e19d6376bbe0120289b6d39a35de15b68d00713f821ab0c7f28f85a31ee" nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string5 = "5A403F3C-9136-4B67-A94E-02D3BCD3162D" nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string6 = "Pspersist-main" nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string7 = /PSprofile\.cpp/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string8 = /Start\sMenu\\Programs\\Startup\\Loader\.exe/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string9 = "TheD1rkMtr/Pspersist" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
