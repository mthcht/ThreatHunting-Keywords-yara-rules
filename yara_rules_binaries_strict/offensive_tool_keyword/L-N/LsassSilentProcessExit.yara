rule LsassSilentProcessExit
{
    meta:
        description = "Detection patterns for the tool 'LsassSilentProcessExit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LsassSilentProcessExit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string1 = /\/LsassSilentProcessExit\.git/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string2 = /\\LsassSilentProcessExit/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string3 = /\\SilentProcessExit\.sln/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string4 = "887e0ff0707e46e7f309f6e12eaddd4161b6b3aa88a705857ac55590cdc4c64a" nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string5 = "daf3ed8ab5cb22d59e4b1de343f15e343c7e2383547f38f550b1e18a3cf8d11d" nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string6 = "deepinstinct/LsassSilentProcessExit" nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string7 = "E82BCAD1-0D2B-4E95-B382-933CF78A8128" nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string8 = /LsassSilentProcessExit\.cpp/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string9 = /LsassSilentProcessExit\.exe/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string10 = /LsassSilentProcessExit\.vcxproj/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string11 = "LsassSilentProcessExit-master" nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string12 = /Setting\sup\sGFlags\s\&\sSilentProcessExit\ssettings\sin\sregistry\?/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string13 = /SilentProcessExitRegistrySetter\.cpp/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string14 = /SilentProcessExitRegistrySetter\.exe/ nocase ascii wide
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
