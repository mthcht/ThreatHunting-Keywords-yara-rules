rule pwdump
{
    meta:
        description = "Detection patterns for the tool 'pwdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: https://ftp.samba.org/pub/samba/pwdump/
        $string1 = /4747b86b7a8d2ba61f377e2526d6f2764cb8146be5dd8d6ad42af745dd705c8b/ nocase ascii wide
        // Description: a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: https://ftp.samba.org/pub/samba/pwdump/
        $string2 = /PWDump/ nocase ascii wide
        // Description: a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: https://ftp.samba.org/pub/samba/pwdump/
        $string3 = /PWDump\./ nocase ascii wide

    condition:
        any of them
}
