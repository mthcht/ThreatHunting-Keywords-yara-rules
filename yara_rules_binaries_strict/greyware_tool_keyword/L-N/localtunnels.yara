rule localtunnels
{
    meta:
        description = "Detection patterns for the tool 'localtunnels' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtunnels"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string1 = " install localtunnel" nocase ascii wide
        // Description: server for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/server
        $string2 = " localtunnel-server" nocase ascii wide
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string3 = /\/localtunnel\.git/ nocase ascii wide
        // Description: server for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/server
        $string4 = /\/localtunnel\-server\.git/ nocase ascii wide
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string5 = "37e85dd1f3987fcc566c1b29bda5b94e4b2fd129a39cc7eeba3af7a69a0cdb09" nocase ascii wide
        // Description: server for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/server
        $string6 = "6f44dd5e572279979a9a59b0186a9fb2805be4c6decbcc438cf2b9d2c17f3a42" nocase ascii wide
        // Description: server for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/server
        $string7 = "aba729428bafe6508191a79e06c7399a19cf80bf0c382eecca951655aab6e00a" nocase ascii wide
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string8 = "bin/lt --host https://" nocase ascii wide
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string9 = /https\:\/\/.{0,100}\.localtunnel\.me/ nocase ascii wide
        // Description: server for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/server
        $string10 = /https\:\/\/localtunnel\.me/ nocase ascii wide
        // Description: server for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/server
        $string11 = /localtunnel\.github\.io\/www\// nocase ascii wide
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string12 = "localtunnel/localtunnel" nocase ascii wide
        // Description: server for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/server
        $string13 = "localtunnel/nginx" nocase ascii wide
        // Description: server for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/server
        $string14 = "localtunnel/server" nocase ascii wide
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string15 = "npm install -g localtunnel" nocase ascii wide
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string16 = "npm install -g localtunnel" nocase ascii wide
        // Description: client for localtunnel.me - localtunnel exposes your localhost to the world for easy testing and sharing
        // Reference: https://github.com/localtunnel/localtunnel
        $string17 = "npx localtunnel --port " nocase ascii wide
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
