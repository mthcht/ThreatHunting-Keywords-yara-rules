rule wmiexec
{
    meta:
        description = "Detection patterns for the tool 'wmiexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: potential wmiexec commandline pattern
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string1 = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__16.{0,100}\s2\>\&1/ nocase ascii wide
        // Description: potential wmiexec commandline pattern
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string2 = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__17.{0,100}\s2\>\&1/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string3 = "/wmiexec/" nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string4 = /cmd\.exe\s\/Q\s\/c\s.{0,100}\.bat\s.{0,100}\>\s\\\\127\.0\.0\.1\\ADMIN\$\\.{0,100}\s2\&/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string5 = /cmd\.exe\s\/Q\s\/c\s\/start\s\/min\spowershell\.exe\s\-nop\s\-c/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string6 = /cmd\.exe\s\/Q\s\/c\shostname1\>\s.{0,100}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,100}\s2\>/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string7 = /cmd\.exe\s\/Q\s\/c\snslookup\s1\>\s.{0,100}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,100}\s2\>/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string8 = /cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-nop\s\-w\s\-hidden\s\-c.{0,100}IEX/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string9 = /cmd\.exe\s\/Q\s\/c\spowershelll\.exe\s1\>\s.{0,100}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,100}\s2\>/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string10 = /cmd\.exe\s\/Q\s\/c\squser\s1\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string11 = /WMIExec\.git/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string12 = /wmiexec_scheduledjob\.py/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string13 = /wmiexec_win32process\.py/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string14 = "WMIExec-main" nocase ascii wide
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
