rule dns_black_cat
{
    meta:
        description = "Detection patterns for the tool 'dns-black-cat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns-black-cat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string1 = " DNS-Black-CAT Server " nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string2 = /\/DBC\-Server\.py/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string3 = /\/dns\-black\-cat\.git/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string4 = /\/dns\-cat\.exe/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string5 = /\\dns\-cat\.exe/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string6 = /agent\.exe\s\-dns\s\-srvhost\s/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string7 = /dns_server\.py\s\-d\s/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string8 = "dns-black-cat-main" nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string9 = /dns\-cat\.exe\s\-/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string10 = "lawrenceamer/dns-black-cat" nocase ascii wide
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
