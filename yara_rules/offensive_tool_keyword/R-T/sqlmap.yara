rule sqlmap
{
    meta:
        description = "Detection patterns for the tool 'sqlmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string1 = " --batch --dbs"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string2 = " --batch --password"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string3 = " --check-tor "
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string4 = " --crawl="
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string5 = " --dbms=mysql -u "
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string6 = " --msf-path"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string7 = " --os-bof"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string8 = " --os-cmd whoami"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string9 = " --os-pwn"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string10 = " --os-smbrelay"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string11 = " --priv-esc"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string12 = " --random-agent "
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string13 = " --sql-shell"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string14 = " --tor "
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string15 = " --tor-port"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string16 = " --tor-type"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string17 = /\s\-u\s.{0,1000}http.{0,1000}\s\-\-dbs/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string18 = /\s\-u\s.{0,1000}http.{0,1000}\s\-\-os\-shell/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string19 = /\s\-\-union\-char\s.{0,1000}GsFRts2/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string20 = "/Sqlmap"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string21 = /\/vulnserver\.py/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string22 = /backdoor\.asp/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string23 = /backdoor\.aspx/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string24 = /backdoor\.jsp/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string25 = /backdoor\.php/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string26 = "--batch --dump -T "
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string27 = "data/shell/backdoors"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string28 = "data/shell/stagers"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string29 = "--file-read=/etc/passwd"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string30 = /icmpsh\.exe/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string31 = /icmpsh_m\.py/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string32 = /icmpsh\-m\.c/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string33 = /icmpsh\-m\.pl/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string34 = /shellcodeexec\.x32/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string35 = /shellcodeexec\.x64/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string36 = "sqlmap -"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string37 = /sqlmap\.conf/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string38 = /sqlmap\.py/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string39 = "sqlmapapi -"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string40 = /sqlmapapi\.py/
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string41 = "sqlmapproject/sqlmap"
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string42 = /xforwardedfor\.py/

    condition:
        any of them
}
