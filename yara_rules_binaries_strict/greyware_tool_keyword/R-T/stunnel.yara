rule stunnel
{
    meta:
        description = "Detection patterns for the tool 'stunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string1 = /\srsync\.stunnel\.org\:\:stunnel\s/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string2 = /\/stunnel\-.{0,100}\.tar\.gz/
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string3 = /\/stunnel\-latest\.tar\.gz/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string4 = /\/stunnel\-latest\-android\.zip/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string5 = /\/stunnel\-latest\-win64\-installer\.exe/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string6 = "/tmp/stunnel"
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string7 = /\\CurrentVersion\\Uninstall\\stunnel/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string8 = /\\Program\sFiles\s\(x86\)\\stunnel\\/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string9 = /\\SOFTWARE\\WOW6432Node\\NSIS_stunnel\\/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string10 = /\\stunnel\-.{0,100}\-win64\-installer\.exe/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string11 = /\\stunnel\\config\\stunnel\.pem/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string12 = /\\stunnel\-latest\-win64\-installer\.exe/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string13 = /\\tstunnel\.exe/ nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string14 = "719e6b5eedc0d4b178d6f0f999555fc3292a22747f3ed2238d529604ee1a5532" nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string15 = "bc917c3bcd943a4d632360c067977a31e85e385f5f4845f69749bce88183cb38" nocase ascii wide
        // Description: Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs
        // Reference: https://www.stunnel.org/index.html
        $string16 = "d686b1a4135947718e7a8157a8cb6694ed50e2267713de1972941148a8859789" nocase ascii wide
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
