rule NTDLLReflection
{
    meta:
        description = "Detection patterns for the tool 'NTDLLReflection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTDLLReflection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string1 = " NtCr3at3Thr3adEx @ " nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string2 = /\/NTDLLReflection\.git/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string3 = "9D365106-D7B8-4B5E-82CC-6D6ABCDCA2B8" nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string4 = "NTDLLReflection-main" nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string5 = "NtWa1tF0rS1ngle0bj3ct Executed" nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string6 = /ReflectiveNTDLL\.cpp/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string7 = /ReflectiveNTDLL\.exe/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string8 = /ReflectiveNTDLL\.sln/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string9 = /ReflectiveNTDLL\.vcxproj/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string10 = "TheD1rkMtr/NTDLLReflection" nocase ascii wide
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
