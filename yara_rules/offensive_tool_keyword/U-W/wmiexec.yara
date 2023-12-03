rule wmiexec
{
    meta:
        description = "Detection patterns for the tool 'wmiexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string1 = /.{0,1000}\/wmiexec\/.{0,1000}/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string2 = /.{0,1000}cmd\.exe\s\/Q\s\/c\s.{0,1000}\.bat\s.{0,1000}\>\s\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\&.{0,1000}/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string3 = /.{0,1000}cmd\.exe\s\/Q\s\/c\s\/start\s\/min\spowershell\.exe\s\-nop\s\-c.{0,1000}/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string4 = /.{0,1000}cmd\.exe\s\/Q\s\/c\shostname1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>.{0,1000}/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string5 = /.{0,1000}cmd\.exe\s\/Q\s\/c\snslookup\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>.{0,1000}/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string6 = /.{0,1000}cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-nop\s\-w\s\-hidden\s\-c.{0,1000}IEX.{0,1000}/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string7 = /.{0,1000}cmd\.exe\s\/Q\s\/c\spowershelll\.exe\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>.{0,1000}/ nocase ascii wide
        // Description: wmiexec.py from impacket used by metasploit
        // Reference: https://github.com/rapid7/metasploit-framework/blob/2722067108b5c034da9f77b95eaf1c1db33db4fa/modules/auxiliary/scanner/smb/impacket/wmiexec.py#L127
        $string8 = /.{0,1000}cmd\.exe\s\/Q\s\/c\squser\s1\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string9 = /.{0,1000}WMIExec\.git.{0,1000}/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string10 = /.{0,1000}wmiexec_scheduledjob\.py.{0,1000}/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string11 = /.{0,1000}wmiexec_win32process\.py.{0,1000}/ nocase ascii wide
        // Description: Set of python scripts which perform different ways of command execution via WMI protocol
        // Reference: https://github.com/WKL-Sec/wmiexec
        $string12 = /.{0,1000}WMIExec\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
