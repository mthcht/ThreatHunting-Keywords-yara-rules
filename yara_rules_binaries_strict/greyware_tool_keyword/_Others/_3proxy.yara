rule _3proxy
{
    meta:
        description = "Detection patterns for the tool '3proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "3proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string1 = /\/3proxy\-.{0,100}\.deb/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string2 = /\/3proxy\-.{0,100}\.rpm/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string3 = /\/3proxy\-.{0,100}\.zip/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string4 = /\/3proxy\.exe/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string5 = /\/3proxy\.git/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string6 = /\/3proxy\.log/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string7 = /\/etc\/3proxy\/conf/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string8 = /\\3proxy\-.{0,100}\.deb/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string9 = /\\3proxy\-.{0,100}\.rpm/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string10 = /\\3proxy\-.{0,100}\.zip/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string11 = /\\3proxy\.cfg/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string12 = /\\3proxy\.exe/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string13 = /\\3proxy\.key/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string14 = /\\3proxy\.log/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string15 = /\\bin\\3proxy/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string16 = /128s3proxy\.key\\"/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string17 = /3proxy\s\-\-install/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string18 = /3proxy\s\-\-remove/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string19 = /3proxy\stiny\sproxy\sserver/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string20 = /3proxy\sWindows\sAuthentication\splugin/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string21 = /3proxy\.exe\s\-\-/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string22 = /3proxy\.service/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string23 = /3proxy\/3proxy/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string24 = /3proxy\@3proxy\.org/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string25 = /add3proxyuser\.sh/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
