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
        $string1 = /.{0,1000}\.\/t14m4t\s.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string2 = /.{0,1000}Wordlist\/ftp_p\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string3 = /.{0,1000}Wordlist\/ftp_u\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string4 = /.{0,1000}Wordlist\/ftp_up\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string5 = /.{0,1000}Wordlist\/mssql_up\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string6 = /.{0,1000}Wordlist\/mysql_up\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string7 = /.{0,1000}Wordlist\/oracle_up\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string8 = /.{0,1000}Wordlist\/pass\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string9 = /.{0,1000}Wordlist\/pop_p\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string10 = /.{0,1000}Wordlist\/pop_u\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string11 = /.{0,1000}Wordlist\/postgres_up\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string12 = /.{0,1000}Wordlist\/smtp_p\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string13 = /.{0,1000}Wordlist\/smtp_u\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string14 = /.{0,1000}Wordlist\/snmp\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string15 = /.{0,1000}Wordlist\/sql_p\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string16 = /.{0,1000}Wordlist\/sql_u\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string17 = /.{0,1000}Wordlist\/ssh_p\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string18 = /.{0,1000}Wordlist\/ssh_u\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string19 = /.{0,1000}Wordlist\/ssh_up\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string20 = /.{0,1000}Wordlist\/telnet_p\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string21 = /.{0,1000}Wordlist\/telnet_u\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string22 = /.{0,1000}Wordlist\/telnet_up\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string23 = /.{0,1000}Wordlist\/user\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string24 = /.{0,1000}Wordlist\/vnc_p\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string25 = /.{0,1000}Wordlist\/windows_u\.txt.{0,1000}/ nocase ascii wide
        // Description: Automated brute-forcing attack tool.
        // Reference: https://github.com/MS-WEB-BN/t14m4t
        $string26 = /.{0,1000}Wordlist\/windows_up\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
