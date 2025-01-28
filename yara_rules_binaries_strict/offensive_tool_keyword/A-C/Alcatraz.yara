rule Alcatraz
{
    meta:
        description = "Detection patterns for the tool 'Alcatraz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alcatraz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string1 = /\sAlcatraz\.exe/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string2 = /\/Alcatraz\.exe/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string3 = /\/Alcatraz\.git/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string4 = /\/Alcatraz\/files\/.{0,100}\/Alcatraz\.zip/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string5 = "/Alcatraz/x64" nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string6 = "/Alcatraz-gui" nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string7 = /\/obfuscator\/obfuscator\./ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string8 = /\\Alcatraz\.exe/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string9 = /Alcatraz\.sln/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string10 = /Alcatraz\.vcxproj/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string11 = "Alcatraz/obfuscator" nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string12 = /Alcatraz\-master\.zip/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string13 = /obfuscator.{0,100}antidisassembly\./ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string14 = /obfuscator\.cpp/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string15 = "weak1337/Alcatraz" nocase ascii wide
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
