rule wapiti
{
    meta:
        description = "Detection patterns for the tool 'wapiti' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wapiti"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string1 = " --flush-attacks" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string2 = " install wapiti3" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string3 = " --max-attack-time" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string4 = " --skip-crawl" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string5 = "/bin/wapiti"
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string6 = /\/data\/attacks\/.{0,100}\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string7 = "/wapitiCore/" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string8 = "/wapiti-scanner/" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string9 = /blindSQLPayloads\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string10 = /busterPayloads\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string11 = "downloads/wapiti-code" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string12 = /drupal_enum\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string13 = /execPayloads\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string14 = /from\swapitiCore\./ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string15 = "import wapiti" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string16 = "install wapiti" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string17 = /log4shell\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string18 = /mod_buster\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string19 = /mod_nikto\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string20 = /mod_shellshock\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string21 = /mod_wp_enum\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string22 = /sql_persister\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string23 = /subdomain_takeovers\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string24 = /subdomain\-wordlist\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string25 = /test_crawler\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string26 = "venv wapiti3" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string27 = "wapiti -u" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string28 = /wapiti\.git/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string29 = /wapiti\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string30 = /wapiti3\-.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string31 = /wapiti3\-.{0,100}\-any\.whl/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string32 = "wapiti3/bin" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string33 = "wapiti-getcookie" nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string34 = /wappalyzer\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string35 = /xxePayloads\.ini/ nocase ascii wide
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
