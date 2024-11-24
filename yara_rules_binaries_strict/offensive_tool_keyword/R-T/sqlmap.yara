rule sqlmap
{
    meta:
        description = "Detection patterns for the tool 'sqlmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string1 = " --batch --dbs" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string2 = " --batch --password" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string3 = " --check-tor " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string4 = " --crawl=" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string5 = " --dbms=mysql -u " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string6 = " --msf-path" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string7 = " --os-bof" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string8 = " --os-cmd whoami" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string9 = " --os-pwn" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string10 = " --os-smbrelay" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string11 = " --priv-esc" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string12 = " --random-agent " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string13 = " --sql-shell" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string14 = " --tor " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string15 = " --tor-port" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string16 = " --tor-type" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string17 = /\s\-u\s.{0,100}http.{0,100}\s\-\-dbs/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string18 = /\s\-u\s.{0,100}http.{0,100}\s\-\-os\-shell/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string19 = /\s\-\-union\-char\s.{0,100}GsFRts2/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string20 = "/Sqlmap" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string21 = /\/vulnserver\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string22 = /backdoor\.asp/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string23 = /backdoor\.aspx/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string24 = /backdoor\.jsp/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string25 = /backdoor\.php/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string26 = "--batch --dump -T " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string27 = "data/shell/backdoors" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string28 = "data/shell/stagers" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string29 = "--file-read=/etc/passwd" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string30 = /icmpsh\.exe/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string31 = /icmpsh_m\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string32 = /icmpsh\-m\.c/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string33 = /icmpsh\-m\.pl/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string34 = /shellcodeexec\.x32/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string35 = /shellcodeexec\.x64/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string36 = "sqlmap -" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string37 = /sqlmap\.conf/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string38 = /sqlmap\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string39 = "sqlmapapi -" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string40 = /sqlmapapi\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string41 = "sqlmapproject/sqlmap" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string42 = /xforwardedfor\.py/ nocase ascii wide
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
