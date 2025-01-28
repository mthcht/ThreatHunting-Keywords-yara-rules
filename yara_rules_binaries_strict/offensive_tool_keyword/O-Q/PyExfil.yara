rule PyExfil
{
    meta:
        description = "Detection patterns for the tool 'PyExfil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyExfil"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string1 = /\/audio\/exfiltrator\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string2 = /\/bgp_exfil\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string3 = /\/http_exfiltration\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string4 = /\/icmp_exfiltration\.py/
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string5 = /\/pop_exfil_client\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string6 = /\/pop_exfil_server\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string7 = /\/PyExfil\.git/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string8 = "/PyExfil/pyexfil/" nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string9 = /\/spoofIPs_client\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string10 = /\/wifiPayload\/client\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string11 = /\/wifiPayload\/server\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string12 = /\\audio\\exfiltrator\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string13 = /\\bgp_exfil\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string14 = /\\http_exfiltration\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string15 = /\\icmp_exfiltration\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string16 = /\\pop_exfil_client\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string17 = /\\pop_exfil_server\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string18 = /\\PyExfil\\pyexfil\\/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string19 = /\\spoofIPs_client\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string20 = /\\wifiPayload\\client\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string21 = /\\wifiPayload\\server\.py/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string22 = /A\sPython\spackage\sfor\sdata\sexfiltration\./ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string23 = "cd PyExfil" nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string24 = /encode\sbaseImage\.jpg\s\/etc\/passwd\snewImage\.jpg/
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string25 = "FILE_TO_EXFIL = \"" nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string26 = "pip install --user PyExfil" nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string27 = /pyexfil\.Comm\.AllJoyn/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string28 = /pyexfil\.Comm\.DNSoTLS\.client/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string29 = /pyexfil\.Comm\.DNSoTLS\.server/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string30 = /pyexfil\.Comm\.GQUIC/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string31 = /pyexfil\.Comm\.jetdirect\.communicator/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string32 = /pyexfil\.Comm\.MDNS/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string33 = /pyexfil\.Comm\.NTP_Body\.client/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string34 = /pyexfil\.Comm\.NTP_Body\.server/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string35 = /pyexfil\.HTTPS\.https_client/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string36 = /pyexfil\.HTTPS\.https_server/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string37 = /pyexfil\.includes\.data_generator/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string38 = /pyexfil\.includes\.encryption_wrappers/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string39 = /pyexfil\.includes\.exceptions/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string40 = /pyexfil\.includes\.general/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string41 = /pyexfil\.includes\.image_manipulation/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string42 = /pyexfil\.includes\.prepare/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string43 = /PyExfil\.MoriRT\.com/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string44 = /pyexfil\.network/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string45 = /pyexfil\.network\.DB_LSP\.dblsp/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string46 = /pyexfil\.network\.FTP\.ftp_exfil/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string47 = /pyexfil\.network\.HTTP_Cookies\.http_exfiltration/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string48 = /pyexfil\.network\.HTTPResp\.client/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string49 = /pyexfil\.network\.ICMP\.icmp_exfiltration/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string50 = /pyexfil\.network\.SpoofIP\.spoofIPs_client/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string51 = /pyexfil\.physical\.qr\.generator/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string52 = /pyexfil\.physical\.wifiPayload\.client/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string53 = /pyexfil\.Stega\.binoffset\.binoffset/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string54 = "PYEXFIL_DEFAULT_PASSWORD" nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string55 = /pyExfil\-latest\.zip/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string56 = "PyExfil-master" nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string57 = "ytisf/PyExfil" nocase ascii wide
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
