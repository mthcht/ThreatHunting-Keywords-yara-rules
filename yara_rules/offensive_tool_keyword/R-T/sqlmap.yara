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
        $string1 = " --batch --dbs" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string2 = " --batch --password" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string3 = " --check-tor " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string4 = " --crawl=" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string5 = " --dbms=mysql -u " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string6 = " --msf-path" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string7 = " --os-bof" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string8 = " --os-cmd whoami" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string9 = " --os-pwn" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string10 = " --os-smbrelay" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string11 = " --priv-esc" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string12 = " --random-agent " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string13 = " --sql-shell" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string14 = " --tor " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string15 = " --tor-port" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string16 = " --tor-type" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string17 = /\s\-u\s.{0,1000}http.{0,1000}\s\-\-dbs/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string18 = /\s\-u\s.{0,1000}http.{0,1000}\s\-\-os\-shell/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string19 = /\s\-\-union\-char\s.{0,1000}GsFRts2/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string20 = "/Sqlmap" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string21 = /\/vulnserver\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string22 = /backdoor\.asp/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string23 = /backdoor\.aspx/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string24 = /backdoor\.jsp/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string25 = /backdoor\.php/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string26 = "--batch --dump -T " nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string27 = "data/shell/backdoors" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string28 = "data/shell/stagers" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string29 = "--file-read=/etc/passwd" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string30 = /icmpsh\.exe/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string31 = /icmpsh_m\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string32 = /icmpsh\-m\.c/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string33 = /icmpsh\-m\.pl/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string34 = /shellcodeexec\.x32/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string35 = /shellcodeexec\.x64/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string36 = "sqlmap -" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string37 = /sqlmap\.conf/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string38 = /sqlmap\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string39 = "sqlmapapi -" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string40 = /sqlmapapi\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string41 = "sqlmapproject/sqlmap" nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string42 = /xforwardedfor\.py/ nocase ascii wide

    condition:
        any of them
}
