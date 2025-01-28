rule Get_NetNTLM
{
    meta:
        description = "Detection patterns for the tool 'Get-NetNTLM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-NetNTLM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string1 = /\sGet\-NetNTLM\.ps1/ nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string2 = /\/Get\-NetNTLM\.git/ nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string3 = /\/Get\-NetNTLM\.ps1/ nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string4 = /\\Get\-NetNTLM\.ps1/ nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string5 = "cba7954a3a44198ede1f02ab8b4ce571d089b72b1dab61bd5cf004958a5e1172" nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string6 = "elnerd/Get-NetNTLM" nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string7 = "Get-NetNTLM-Hash " nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string8 = /NTLM\sTlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA\+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA\=\=/ nocase ascii wide
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
