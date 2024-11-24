rule rsocks
{
    meta:
        description = "Detection patterns for the tool 'rsocks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsocks"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string1 = /\srsocks\.pool/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string2 = /\srsocks\.server/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string3 = /\.rsocks\.plist/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string4 = "/bin/rsocks" nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string5 = /\/com\.tonyseek\.rsocks\.plist/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string6 = "/opt/rsocks/" nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string7 = /\/rsocks\.git/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string8 = /\/rsocks\.git/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string9 = /\/rsocks\.toml/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string10 = "/rsocks/releases/download/" nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string11 = "/rsocks_linux_amd64" nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string12 = /\/rsocks_windows_386\.exe/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string13 = /\\rsocks_windows_386\.exe/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string14 = "14586f0477d31640096bf4749480b78c6a6c3afde3527bcc64e9d5f70d9e93ac" nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string15 = "242194dbbdaca6aa7382e0b9f9677a2e7966bc6db8934119aa096e38a9fbf86d" nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string16 = "4a97ad649c31411528694fdd8751bc6521f535f57022e6a6c0a39988df20d7b0" nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string17 = "51a5737c2b51190507d47557023264299f8de0b2152e89e093e0e61f64807986" nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string18 = "a539e169941f55d687ca44c90a5a90715dd23871a04a64f1712e08e758df0ec0" nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string19 = "a9a87bdcf06a8b5ee41a1eec95c0f9c813a5f29ba6d8eec28b07d8331aa5eb85" nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string20 = "brimstone/rsocks" nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string21 = "easy_install rsocks" nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string22 = "import socket, socks, listen, serve, wrap_ssl, GreenPool" nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string23 = "pip install rsocks" nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string24 = "pip install -U rsocks" nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string25 = "rsocks --config" nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string26 = /rsocks\/server\.py/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string27 = /rsocks\\server\.py/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string28 = "tonyseek/rsocks" nocase ascii wide
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
