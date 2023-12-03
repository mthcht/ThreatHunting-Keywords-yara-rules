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
        $string1 = /.{0,1000}\s\-\-batch\s\-\-dbs.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string2 = /.{0,1000}\s\-\-batch\s\-\-password.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string3 = /.{0,1000}\s\-\-check\-tor\s.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string4 = /.{0,1000}\s\-\-crawl\=.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string5 = /.{0,1000}\s\-\-dbms\=mysql\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string6 = /.{0,1000}\s\-\-msf\-path.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string7 = /.{0,1000}\s\-\-os\-bof.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string8 = /.{0,1000}\s\-\-os\-cmd\swhoami.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string9 = /.{0,1000}\s\-\-os\-pwn.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string10 = /.{0,1000}\s\-\-os\-smbrelay.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string11 = /.{0,1000}\s\-\-priv\-esc.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string12 = /.{0,1000}\s\-\-random\-agent\s.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string13 = /.{0,1000}\s\-\-sql\-shell.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string14 = /.{0,1000}\s\-\-tor\s.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string15 = /.{0,1000}\s\-\-tor\-port.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string16 = /.{0,1000}\s\-\-tor\-type.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string17 = /.{0,1000}\s\-u\s.{0,1000}http.{0,1000}\s\-\-dbs/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string18 = /.{0,1000}\s\-u\s.{0,1000}http.{0,1000}\s\-\-os\-shell.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string19 = /.{0,1000}\s\-\-union\-char\s.{0,1000}GsFRts2.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string20 = /.{0,1000}\/Sqlmap.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string21 = /.{0,1000}\/vulnserver\.py.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string22 = /.{0,1000}backdoor\.asp.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string23 = /.{0,1000}backdoor\.aspx.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string24 = /.{0,1000}backdoor\.jsp.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string25 = /.{0,1000}backdoor\.php.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string26 = /.{0,1000}\-\-batch\s\-\-dump\s\-T\s.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string27 = /.{0,1000}data\/shell\/backdoors.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string28 = /.{0,1000}data\/shell\/stagers.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string29 = /.{0,1000}\-\-file\-read\=\/etc\/passwd.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string30 = /.{0,1000}icmpsh\.exe.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string31 = /.{0,1000}icmpsh_m\.py.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string32 = /.{0,1000}icmpsh\-m\.c.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string33 = /.{0,1000}icmpsh\-m\.pl.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string34 = /.{0,1000}shellcodeexec\.x32.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string35 = /.{0,1000}shellcodeexec\.x64.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string36 = /.{0,1000}sqlmap\s\-.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string37 = /.{0,1000}sqlmap\.conf.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string38 = /.{0,1000}sqlmap\.py.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string39 = /.{0,1000}sqlmapapi\s\-.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string40 = /.{0,1000}sqlmapapi\.py/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string41 = /.{0,1000}sqlmapproject\/sqlmap.{0,1000}/ nocase ascii wide
        // Description: Automatic SQL injection and database takeover tool.
        // Reference: https://github.com/sqlmapproject/sqlmap
        $string42 = /.{0,1000}xforwardedfor\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
