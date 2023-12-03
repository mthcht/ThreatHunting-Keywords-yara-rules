rule dsniff
{
    meta:
        description = "Detection patterns for the tool 'dsniff' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsniff"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: password sniffer. handles FTP. Telnet. SMTP. HTTP. POP. poppass. NNTP. IMAP. SNMP. LDAP. Rlogin. RIP. OSPF. PPTP MS-CHAP. NFS. VRRP. YP/NIS. SOCKS. X11. CVS. IRC. AIM. ICQ. Napster. PostgreSQL. Meeting Maker. Citrix ICA. Symantec pcAnywhere. NAI Sniffer. Microsoft SMB. Oracle SQL*Net. Sybase and Microsoft SQL auth info. dsniff automatically detects and minimally parses each application protocol. only saving the interesting bits. and uses Berkeley DB as its output file format. only logging unique authentication attempts. full TCP/IP reassembly is provided by libnids(3) (likewise for the following tools as well).
        // Reference: https://github.com/tecknicaltom/dsniff
        $string1 = /.{0,1000}\/dnsspoof\.c.{0,1000}/ nocase ascii wide
        // Description: password sniffer. handles FTP. Telnet. SMTP. HTTP. POP. poppass. NNTP. IMAP. SNMP. LDAP. Rlogin. RIP. OSPF. PPTP MS-CHAP. NFS. VRRP. YP/NIS. SOCKS. X11. CVS. IRC. AIM. ICQ. Napster. PostgreSQL. Meeting Maker. Citrix ICA. SymantecpcAnywhere. NAI Sniffer. Microsoft SMB. Oracle SQL*Net. Sybase and Microsoft SQL auth info. dsniff automatically detects and minimally parses each application protocol. only saving the interesting bits. and uses Berkeley DB as its output file format. only logging unique authentication attempts. full TCP/IP reassembly is provided by libnids(3) (likewise for the following tools as well).
        // Reference: https://github.com/tecknicaltom/dsniff
        $string2 = /.{0,1000}\/dsniff\.c.{0,1000}/ nocase ascii wide
        // Description: password sniffer. handles FTP. Telnet. SMTP. HTTP. POP. poppass. NNTP. IMAP. SNMP. LDAP. Rlogin. RIP. OSPF. PPTP  MS-CHAP. NFS. VRRP. YP/NIS. SOCKS. X11. CVS. IRC. AIM. ICQ. Napster. PostgreSQL. Meeting Maker. Citrix ICA. Symantec pcAnywhere. NAI Sniffer. Microsoft SMB. Oracle SQL*Net. Sybase and Microsoft SQL auth info. dsniff automatically detects and minimally parses each application protocol. only saving the interesting bits. and uses Berkeley DB as its output file format. only logging unique authentication attempts. full TCP/IP reassembly is provided by libnids(3) (likewise for the following tools as well).
        // Reference: https://github.com/tecknicaltom/dsniff
        $string3 = /.{0,1000}\/dsniff\.services.{0,1000}/ nocase ascii wide
        // Description: password sniffer. handles FTP. Telnet. SMTP. HTTP. POP. poppass. NNTP. IMAP. SNMP. LDAP. Rlogin. RIP. OSPF. PPTP MS-CHAP. NFS. VRRP. YP/NIS. SOCKS. X11. CVS. IRC. AIM. ICQ. Napster. PostgreSQL. Meeting Maker. Citrix ICA. Symantec  pcAnywhere. NAI Sniffer. Microsoft SMB. Oracle SQL*Net. Sybase and Microsoft SQL auth info. dsniff automatically detects and minimally parses each application protocol. only saving the interesting bits. and uses Berkeley DB as its output file format. only logging unique authentication attempts. full TCP/IP reassembly is provided by libnids(3) (likewise for the following tools as well)
        // Reference: https://github.com/tecknicaltom/dsniff
        $string4 = /.{0,1000}tecknicaltom\/dsniff.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
