rule PowerShdll
{
    meta:
        description = "Detection patterns for the tool 'PowerShdll' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShdll"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // Reference: https://github.com/p3nt4/PowerShdll
        $string1 = "36EBF9AA-2F37-4F1D-A2F1-F2A45DEEAF21" nocase ascii wide
        // Description: Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // Reference: https://github.com/p3nt4/PowerShdll
        $string2 = "5067F916-9971-47D6-BBCB-85FB3982584F" nocase ascii wide
        // Description: Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // Reference: https://github.com/p3nt4/PowerShdll
        $string3 = "PowerShdll" nocase ascii wide
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
