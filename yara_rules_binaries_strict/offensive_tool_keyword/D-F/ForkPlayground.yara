rule ForkPlayground
{
    meta:
        description = "Detection patterns for the tool 'ForkPlayground' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ForkPlayground"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string1 = /\sForkDump\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string2 = /\sForkLib\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string3 = /\/ForkDump\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string4 = /\/ForkLib\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string5 = /\/ForkPlayground\.git/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string6 = /\\ForkDump\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string7 = /\\ForkDump\.exe/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string8 = /\\ForkDump\.vcxproj/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string9 = /\\ForkLib\.cpp/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string10 = /\\ForkLib\.vcxproj/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string11 = /\\ForkPlayground\.sln/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string12 = "18C681A2-072F-49D5-9DE6-74C979EAE08B" nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string13 = "AD495F95-007A-4DC1-9481-0689CA0547D9" nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string14 = "D4stiny/ForkPlayground" nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string15 = /ForkDump\-x64\.exe/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string16 = /ForkDump\-x64\.pdb/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string17 = /ForkDump\-x86\.exe/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string18 = /ForkDump\-x86\.pdb/ nocase ascii wide
        // Description: proof-of-concept of Process Forking.
        // Reference: https://github.com/D4stiny/ForkPlayground
        $string19 = "ForkPlayground-master" nocase ascii wide
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
