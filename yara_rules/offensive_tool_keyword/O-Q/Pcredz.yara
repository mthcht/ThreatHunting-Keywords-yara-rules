rule Pcredz
{
    meta:
        description = "Detection patterns for the tool 'Pcredz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pcredz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool extracts Credit card numbers. NTLM(DCE-RPC. HTTP. SQL. LDAP. etc). Kerberos (AS-REQ Pre-Auth etype 23). HTTP Basic. SNMP. POP. SMTP. FTP. IMAP. etc from a pcap file or from a live interface.
        // Reference: https://github.com/lgandx/Pcredz
        $string1 = /\.\/Pcredz\s/
        // Description: This tool extracts Credit card numbers. NTLM(DCE-RPC. HTTP. SQL. LDAP. etc). Kerberos (AS-REQ Pre-Auth etype 23). HTTP Basic. SNMP. POP. SMTP. FTP. IMAP. etc from a pcap file or from a live interface.
        // Reference: https://github.com/lgandx/Pcredz
        $string2 = "lgandx/Pcredz" nocase ascii wide
        // Description: This tool extracts Credit card numbers. NTLM(DCE-RPC. HTTP. SQL. LDAP. etc). Kerberos (AS-REQ Pre-Auth etype 23). HTTP Basic. SNMP. POP. SMTP. FTP. IMAP. etc from a pcap file or from a live interface.
        // Reference: https://github.com/lgandx/Pcredz
        $string3 = "Pcredz -d " nocase ascii wide
        // Description: This tool extracts Credit card numbers. NTLM(DCE-RPC. HTTP. SQL. LDAP. etc). Kerberos (AS-REQ Pre-Auth etype 23). HTTP Basic. SNMP. POP. SMTP. FTP. IMAP. etc from a pcap file or from a live interface.
        // Reference: https://github.com/lgandx/Pcredz
        $string4 = "Pcredz -f " nocase ascii wide
        // Description: This tool extracts Credit card numbers. NTLM(DCE-RPC. HTTP. SQL. LDAP. etc). Kerberos (AS-REQ Pre-Auth etype 23). HTTP Basic. SNMP. POP. SMTP. FTP. IMAP. etc from a pcap file or from a live interface.
        // Reference: https://github.com/lgandx/Pcredz
        $string5 = "Pcredz -i " nocase ascii wide

    condition:
        any of them
}
