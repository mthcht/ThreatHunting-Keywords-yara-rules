rule advanced_ip_scanner
{
    meta:
        description = "Detection patterns for the tool 'advanced-ip-scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced-ip-scanner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string1 = /\.exe\s\/s\:ip_ranges\.txt\s\/f\:scan_results\.txt/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string2 = /\\Advanced\sIP\sScanner\.lnk/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string3 = /\\advanced_ip_scanner/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string4 = /\\Local\\Temp\\Advanced\sIP\sScanner\s2\\/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string5 = /\\Program\sFiles\s\(x86\)\\Advanced\sIP\sScanner\\/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string6 = /\\Programs\\Advanced\sIP\sScanner\sPortable\\/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string7 = /\\Start\sMenu\\Programs\\Advanced\sIP\sScanner\sv2/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string8 = /\>Advanced\sIP\sScanner\sSetup\</ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string9 = /\>Advanced\sIP\sScanner\</ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string10 = /26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string11 = /26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string12 = /Advanced\sIP\sScanner/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string13 = /Advanced_IP_Scanner.{0,100}\.exe/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string14 = /advanced_ip_scanner_console\.exe/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string15 = /https\:\/\/download\.advanced\-ip\-scanner\.com\/download\/files\/.{0,100}\.exe/ nocase ascii wide
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
