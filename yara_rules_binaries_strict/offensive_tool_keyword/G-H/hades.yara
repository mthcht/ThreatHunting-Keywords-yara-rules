rule hades
{
    meta:
        description = "Detection patterns for the tool 'hades' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hades"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string1 = /\.exe.{0,100}\s\-f\s.{0,100}\.bin\s\-t\squeueuserapc/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string2 = /\.exe.{0,100}\s\-t\squeueuserapc/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string3 = /\.exe.{0,100}\s\-t\sremotethread/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string4 = /\.exe.{0,100}\s\-t\sselfthread/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string5 = /\.exe.{0,100}\s\-\-technique\squeueuserapc/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string6 = /\.exe.{0,100}\s\-\-technique\sremotethread/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string7 = /\.exe.{0,100}\s\-\-technique\sselfthread/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string8 = /\/cmd\/hades\// nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string9 = /\/hades\.git/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string10 = /\/hades\-main\.zip/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string11 = /\\hades\.exe/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string12 = /\\hades\-main\.zip/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string13 = /f1zm0\/hades/ nocase ascii wide
        // Description: Go shellcode loader that combines multiple evasion techniques
        // Reference: https://github.com/f1zm0/hades
        $string14 = /hades_directsys\.exe/ nocase ascii wide
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
