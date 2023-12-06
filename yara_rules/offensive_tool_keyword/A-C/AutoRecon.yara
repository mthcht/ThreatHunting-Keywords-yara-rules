rule AutoRecon
{
    meta:
        description = "Detection patterns for the tool 'AutoRecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoRecon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string1 = /\sautorecon\.py\s/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string2 = /\/AutoRecon\.git/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string3 = /\/bruteforce\-ftp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string4 = /\/bruteforce\-http\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string5 = /\/bruteforce\-rdp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string6 = /\/bruteforce\-smb\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string7 = /\/bruteforce\-ssh\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string8 = /\/dirbuster\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string9 = /\/dnsrecon\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string10 = /\/dnsrecon\-subdomain\-bruteforce\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string11 = /\/dns\-zone\-transfer\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string12 = /\/enum4linux\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string13 = /\/oracle\-patator\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string14 = /\/oracle\-scanner\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string15 = /\/oracle\-tnscmd\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string16 = /\/rpcdump\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string17 = /\/rsync\-list\-files\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string18 = /\/sipvicious\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string19 = /\/smbmap\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string20 = /\/smb\-vuln\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string21 = /\/wpscan\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string22 = /\\AutoRecon\-main/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string23 = /\\bruteforce\-ftp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string24 = /\\bruteforce\-http\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string25 = /\\bruteforce\-rdp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string26 = /\\bruteforce\-smb\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string27 = /\\bruteforce\-ssh\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string28 = /\\dirbuster\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string29 = /\\dnsrecon\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string30 = /\\dnsrecon\-subdomain\-bruteforce\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string31 = /\\dns\-zone\-transfer\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string32 = /\\enum4linux\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string33 = /\\ldap\-search\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string34 = /\\lookup\-sid\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string35 = /\\nbtscan\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string36 = /\\nikto\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string37 = /\\nmap\-ajp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string38 = /\\nmap\-cassandra\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string39 = /\\nmap\-cups\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string40 = /\\nmap\-distccd\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string41 = /\\nmap\-dns\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string42 = /\\nmap\-finger\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string43 = /\\nmap\-ftp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string44 = /\\nmap\-http\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string45 = /\\nmap\-imap\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string46 = /\\nmap\-irc\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string47 = /\\nmap\-kerberos\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string48 = /\\nmap\-ldap\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string49 = /\\nmap\-mongodb\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string50 = /\\nmap\-mountd\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string51 = /\\nmap\-msrpc\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string52 = /\\nmap\-mssql\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string53 = /\\nmap\-multicast\-dns\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string54 = /\\nmap\-mysql\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string55 = /\\nmap\-nfs\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string56 = /\\nmap\-nntp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string57 = /\\nmap\-ntp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string58 = /\\nmap\-oracle\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string59 = /\\nmap\-pop3\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string60 = /\\nmap\-rdp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string61 = /\\nmap\-redis\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string62 = /\\nmap\-rmi\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string63 = /\\nmap\-rsync\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string64 = /\\nmap\-sip\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string65 = /\\nmap\-smb\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string66 = /\\nmap\-smtp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string67 = /\\nmap\-snmp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string68 = /\\nmap\-ssh\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string69 = /\\nmap\-telnet\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string70 = /\\nmap\-tftp\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string71 = /\\nmap\-vnc\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string72 = /\\onesixtyone\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string73 = /\\oracle\-patator\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string74 = /\\oracle\-scanner\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string75 = /\\oracle\-tnscmd\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string76 = /\\rpcdump\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string77 = /\\smbmap\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string78 = /_smtp_user\-enum_hydra_/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string79 = /_snmp_snmpwalk\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string80 = /_snmp_snmpwalk_process_paths\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string81 = /_snmp_snmpwalk_running_processes\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string82 = /_snmp_snmpwalk_software_names\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string83 = /_snmp_snmpwalk_storage_units\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string84 = /_snmp_snmpwalk_system_processes\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string85 = /_snmp_snmpwalk_tcp_ports\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string86 = /_snmp_snmpwalk_user_accounts\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string87 = /apt\sinstall\sseclists/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string88 = /autorecon\s\-t\s/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string89 = /AutoRecon\\autorecon\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string90 = /darkweb2017\-top100\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string91 = /import.{0,1000}autorecon\.config/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string92 = /import.{0,1000}autorecon\.plugins/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string93 = /pip\suninstall\sautorecon/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string94 = /pipx\supgrade\sautorecon/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string95 = /smbmap\-execute\-command\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string96 = /smbmap\-list\-contents\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string97 = /smbmap\-share\-permissions\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string98 = /smtp\-user\-enum\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string99 = /subdomain\-enumeration\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string100 = /subdomains\-top1million\-110000\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string101 = /Tib3rius\/AutoRecon/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string102 = /top\-usernames\-shortlist\.txt/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string103 = /virtual\-host\-enumeration\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string104 = /winrm\-detection\.py/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string105 = /wkhtmltoimage\.py/ nocase ascii wide

    condition:
        any of them
}
