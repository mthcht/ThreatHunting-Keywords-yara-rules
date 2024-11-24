rule Invisi_Shell
{
    meta:
        description = "Detection patterns for the tool 'Invisi-Shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invisi-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string1 = /\/Invisi\-Shell\.git/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string2 = /\\RunWithPathAsAdmin\.bat/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string3 = /\\RunWithRegistryNonAdmin\.bat/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string4 = "18A66118-B98D-4FFC-AABE-DAFF5779F14C" nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string5 = "4a8e184ca9e1ccc775b224a48d344ce13dde26a86a634df2853ce7a27c17765c" nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string6 = "833d68452ea956b5d23bcb243cd327bd05dfd79fb5a4a34064783749eafa1ddf" nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string7 = "835747f27a37aa3fab9a116d7480701b813c16eba6b903eb82b96fa230aa992e" nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string8 = "835747f27a37aa3fab9a116d7480701b813c16eba6b903eb82b96fa230aa992e" nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string9 = "Invisi-Shell" nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string10 = /InvisiShellProfiler\.cpp/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string11 = /InvisiShellProfiler\.def/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string12 = /InvisiShellProfiler\.dll/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string13 = /InvisiShellProfiler\.h/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string14 = /InvisiShellProfiler\.pdb/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string15 = /InvisiShellProfiler\.vcxproj/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string16 = "OmerYa/Invisi-Shell" nocase ascii wide
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
