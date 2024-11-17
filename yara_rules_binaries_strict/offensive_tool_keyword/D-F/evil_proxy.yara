rule evil_proxy
{
    meta:
        description = "Detection patterns for the tool 'evil-proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evil-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string1 = /\sevil\-proxy/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string2 = /\sevil\-proxy\.rb/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string3 = /\sinstall\sevil\-proxy/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string4 = /\.\/evil\-proxy/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string5 = /\/evil\-proxy\.git/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string6 = /\/evil\-proxy\.rb/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string7 = /\/evil\-proxy\// nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string8 = /\@mitm_pattern\s\=\s/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string9 = /\@mitm_port\s\=\s/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string10 = /\@mitm_servers\s\=/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string11 = /\\evil\-proxy\.rb/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string12 = /\\evil\-proxy\\/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string13 = /\=\s\\"evil\-proxy\\"/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string14 = /127\.0\.0\.1\:\#\{mitm_port\}/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string15 = /A\sruby\shttp\/https\sproxy\sto\sdo\sEVIL\sthings\./ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string16 = /bbtfr\/evil\-proxy/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string17 = /evil\-proxy\.gemspec/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string18 = /evil\-proxy\/agentproxy/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string19 = /evil\-proxy\/httpproxy/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string20 = /evil\-proxy\/selenium/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string21 = /evil\-proxy\/version/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string22 = /EvilProxy\:\:HTTPProxyServer/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string23 = /EvilProxy\:\:MITMProxyServer/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string24 = /evil\-proxy\-0\.1\.0/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string25 = /evil\-proxy\-0\.2\.0/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string26 = /evil\-proxy\-master/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string27 = /gem\s\'evil\-proxy\'/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string28 = /http\:\/\/101\.251\.217\.210/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string29 = /HTTPClient\.post\(\'https\:\/\/httpbin\.org\/post/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string30 = /mitmproxy\.rb/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string31 = /module\sEvilProxy/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string32 = /require\s\'evil\-proxy\'/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string33 = /require\s\'evil\-proxy\/async\'/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string34 = /require\s\'evil\-proxy\/store\'/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string35 = /vil\-proxy\/quickcert/ nocase ascii wide
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
