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
        $string1 = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__16.{0,1000}\s2\>\&1/ nocase ascii wide
        // Description: potential wmiexec commandline pattern
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string2 = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__17.{0,1000}\s2\>\&1/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string3 = /\/wmiexec\// nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string4 = /cmd\.exe\s\/Q\s\/c\s.{0,1000}\.bat\s.{0,1000}\>\s\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\&/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string5 = /cmd\.exe\s\/Q\s\/c\s\/start\s\/min\spowershell\.exe\s\-nop\s\-c/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string6 = /cmd\.exe\s\/Q\s\/c\shostname1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string7 = /cmd\.exe\s\/Q\s\/c\snslookup\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string8 = /cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-nop\s\-w\s\-hidden\s\-c.{0,1000}IEX/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string9 = /cmd\.exe\s\/Q\s\/c\spowershelll\.exe\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
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
        $string14 = /WMIExec\-main/ nocase ascii wide

    condition:
        any of them
}
