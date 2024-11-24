rule yakit
{
    meta:
        description = "Detection patterns for the tool 'yakit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "yakit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string1 = /\sset\-proxy\.ps1/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string2 = "\"http://mitm\"" nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string3 = "/MITMPluginLogViewer" nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string4 = "/MITMServerHijacking" nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string5 = /\/set\-proxy\.ps1/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string6 = /\/yak_darwin_amd64\.zip/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string7 = /\/yak_linux_amd64\.zip/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string8 = /\/yak_windows_amd64\.zip/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string9 = /\?\?\sMITM\s\?\?\?\?/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string10 = /\\default\-yakit\.db/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string11 = /\\set\-proxy\.ps1/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string12 = /\\System32\\yak\.exe/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string13 = /\\yak\.exe/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string14 = "MITMServerHijacking/MITMPluginLocalList" nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string15 = "pwd86u1qwZ9PWevKqm1A3yAw==" nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string16 = "PwDaBjJzgufjES89Rs4Lpq63O300R/kOz30WCLo6BxxX6QVEilwSlpClnG5cZaikTA==" nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string17 = "pWDkVEtllTAK5h6cnhxNxDA==" nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string18 = /Yakit\-.{0,100}\-windows\-amd64\.exe/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string19 = /Yakit\/1\.0\.0/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string20 = "YAKIT_MITM" nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string21 = /yakit\-remote\.json/ nocase ascii wide
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
