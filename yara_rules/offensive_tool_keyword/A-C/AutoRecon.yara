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
        $string1 = /.{0,1000}\sautorecon\.py\s.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string2 = /.{0,1000}\/AutoRecon\.git.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string3 = /.{0,1000}\/bruteforce\-ftp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string4 = /.{0,1000}\/bruteforce\-http\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string5 = /.{0,1000}\/bruteforce\-rdp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string6 = /.{0,1000}\/bruteforce\-smb\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string7 = /.{0,1000}\/bruteforce\-ssh\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string8 = /.{0,1000}\/dirbuster\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string9 = /.{0,1000}\/dnsrecon\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string10 = /.{0,1000}\/dnsrecon\-subdomain\-bruteforce\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string11 = /.{0,1000}\/dns\-zone\-transfer\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string12 = /.{0,1000}\/enum4linux\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string13 = /.{0,1000}\/oracle\-patator\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string14 = /.{0,1000}\/oracle\-scanner\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string15 = /.{0,1000}\/oracle\-tnscmd\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string16 = /.{0,1000}\/rpcdump\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string17 = /.{0,1000}\/rsync\-list\-files\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string18 = /.{0,1000}\/sipvicious\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string19 = /.{0,1000}\/smbmap\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string20 = /.{0,1000}\/smb\-vuln\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string21 = /.{0,1000}\/wpscan\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string22 = /.{0,1000}\\AutoRecon\-main.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string23 = /.{0,1000}\\bruteforce\-ftp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string24 = /.{0,1000}\\bruteforce\-http\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string25 = /.{0,1000}\\bruteforce\-rdp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string26 = /.{0,1000}\\bruteforce\-smb\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string27 = /.{0,1000}\\bruteforce\-ssh\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string28 = /.{0,1000}\\dirbuster\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string29 = /.{0,1000}\\dnsrecon\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string30 = /.{0,1000}\\dnsrecon\-subdomain\-bruteforce\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string31 = /.{0,1000}\\dns\-zone\-transfer\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string32 = /.{0,1000}\\enum4linux\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string33 = /.{0,1000}\\ldap\-search\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string34 = /.{0,1000}\\lookup\-sid\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string35 = /.{0,1000}\\nbtscan\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string36 = /.{0,1000}\\nikto\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string37 = /.{0,1000}\\nmap\-ajp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string38 = /.{0,1000}\\nmap\-cassandra\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string39 = /.{0,1000}\\nmap\-cups\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string40 = /.{0,1000}\\nmap\-distccd\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string41 = /.{0,1000}\\nmap\-dns\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string42 = /.{0,1000}\\nmap\-finger\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string43 = /.{0,1000}\\nmap\-ftp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string44 = /.{0,1000}\\nmap\-http\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string45 = /.{0,1000}\\nmap\-imap\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string46 = /.{0,1000}\\nmap\-irc\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string47 = /.{0,1000}\\nmap\-kerberos\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string48 = /.{0,1000}\\nmap\-ldap\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string49 = /.{0,1000}\\nmap\-mongodb\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string50 = /.{0,1000}\\nmap\-mountd\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string51 = /.{0,1000}\\nmap\-msrpc\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string52 = /.{0,1000}\\nmap\-mssql\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string53 = /.{0,1000}\\nmap\-multicast\-dns\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string54 = /.{0,1000}\\nmap\-mysql\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string55 = /.{0,1000}\\nmap\-nfs\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string56 = /.{0,1000}\\nmap\-nntp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string57 = /.{0,1000}\\nmap\-ntp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string58 = /.{0,1000}\\nmap\-oracle\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string59 = /.{0,1000}\\nmap\-pop3\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string60 = /.{0,1000}\\nmap\-rdp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string61 = /.{0,1000}\\nmap\-redis\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string62 = /.{0,1000}\\nmap\-rmi\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string63 = /.{0,1000}\\nmap\-rsync\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string64 = /.{0,1000}\\nmap\-sip\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string65 = /.{0,1000}\\nmap\-smb\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string66 = /.{0,1000}\\nmap\-smtp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string67 = /.{0,1000}\\nmap\-snmp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string68 = /.{0,1000}\\nmap\-ssh\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string69 = /.{0,1000}\\nmap\-telnet\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string70 = /.{0,1000}\\nmap\-tftp\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string71 = /.{0,1000}\\nmap\-vnc\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string72 = /.{0,1000}\\onesixtyone\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string73 = /.{0,1000}\\oracle\-patator\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string74 = /.{0,1000}\\oracle\-scanner\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string75 = /.{0,1000}\\oracle\-tnscmd\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string76 = /.{0,1000}\\rpcdump\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string77 = /.{0,1000}\\smbmap\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string78 = /.{0,1000}_smtp_user\-enum_hydra_.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string79 = /.{0,1000}_snmp_snmpwalk\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string80 = /.{0,1000}_snmp_snmpwalk_process_paths\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string81 = /.{0,1000}_snmp_snmpwalk_running_processes\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string82 = /.{0,1000}_snmp_snmpwalk_software_names\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string83 = /.{0,1000}_snmp_snmpwalk_storage_units\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string84 = /.{0,1000}_snmp_snmpwalk_system_processes\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string85 = /.{0,1000}_snmp_snmpwalk_tcp_ports\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string86 = /.{0,1000}_snmp_snmpwalk_user_accounts\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string87 = /.{0,1000}apt\sinstall\sseclists.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string88 = /.{0,1000}autorecon\s\-t\s.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string89 = /.{0,1000}AutoRecon\\autorecon\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string90 = /.{0,1000}darkweb2017\-top100\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string91 = /.{0,1000}import.{0,1000}autorecon\.config.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string92 = /.{0,1000}import.{0,1000}autorecon\.plugins.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string93 = /.{0,1000}pip\suninstall\sautorecon.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string94 = /.{0,1000}pipx\supgrade\sautorecon.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string95 = /.{0,1000}smbmap\-execute\-command\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string96 = /.{0,1000}smbmap\-list\-contents\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string97 = /.{0,1000}smbmap\-share\-permissions\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string98 = /.{0,1000}smtp\-user\-enum\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string99 = /.{0,1000}subdomain\-enumeration\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string100 = /.{0,1000}subdomains\-top1million\-110000\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string101 = /.{0,1000}Tib3rius\/AutoRecon.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string102 = /.{0,1000}top\-usernames\-shortlist\.txt.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string103 = /.{0,1000}virtual\-host\-enumeration\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string104 = /.{0,1000}winrm\-detection\.py.{0,1000}/ nocase ascii wide
        // Description: AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
        // Reference: https://github.com/Tib3rius/AutoRecon
        $string105 = /.{0,1000}wkhtmltoimage\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
