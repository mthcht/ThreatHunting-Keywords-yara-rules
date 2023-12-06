rule t14m4t
{
    meta:
        description = "Detection patterns for the tool 't14m4t' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "t14m4t"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string1 = /\.\/t14m4t\s/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string2 = /Wordlist\/ftp_p\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string3 = /Wordlist\/ftp_u\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string4 = /Wordlist\/ftp_up\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string5 = /Wordlist\/mssql_up\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string6 = /Wordlist\/mysql_up\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string7 = /Wordlist\/oracle_up\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string8 = /Wordlist\/pass\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string9 = /Wordlist\/pop_p\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string10 = /Wordlist\/pop_u\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string11 = /Wordlist\/postgres_up\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string12 = /Wordlist\/smtp_p\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string13 = /Wordlist\/smtp_u\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string14 = /Wordlist\/snmp\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string15 = /Wordlist\/sql_p\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string16 = /Wordlist\/sql_u\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string17 = /Wordlist\/ssh_p\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string18 = /Wordlist\/ssh_u\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string19 = /Wordlist\/ssh_up\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string20 = /Wordlist\/telnet_p\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string21 = /Wordlist\/telnet_u\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string22 = /Wordlist\/telnet_up\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string23 = /Wordlist\/user\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string24 = /Wordlist\/vnc_p\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string25 = /Wordlist\/windows_u\.txt/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string26 = /Wordlist\/windows_up\.txt/ nocase ascii wide

    condition:
        any of them
}
