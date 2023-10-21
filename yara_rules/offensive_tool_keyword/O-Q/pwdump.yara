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
        $string1 = /PWDump\./ nocase ascii wide

    condition:
        any of them
}