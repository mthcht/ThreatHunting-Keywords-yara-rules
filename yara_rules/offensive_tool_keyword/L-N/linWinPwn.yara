rule linWinPwn
{
    meta:
        description = "Detection patterns for the tool 'linWinPwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linWinPwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string1 = /\saad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string2 = /\s\-\-asreproast\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string3 = /\scoerce\s.*\s\-\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string4 = /\s\-\-dc\s.*\s\-m\scustom\s\-\-filter\s.*objectCategory/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string5 = /\s\-dc\-ip\s.*\s\-dump\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string6 = /\s\-\-dc\-ip\s.*\s\-\-vuln\s\-\-enabled/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string7 = /\s\-dc\-ip\s.*SAMDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string8 = /\s\-\-force\-kerb\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string9 = /\s\-\-format\=krb5asrep.*\s\-\-wordlist\=/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string10 = /\s\-g\s\-n\s\-\-kerberoast/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string11 = /\s\-\-impersonate\sAdministrator\s\-shell\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string12 = /\s\-ip\s.*\s\-smb2support\s.*lwpshare.*\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string13 = /\sldap\s.*\s\-\-gmsa\s.*dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string14 = /\slinWinPwn/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string15 = /\s\-M\sdfscoerce\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string16 = /\s\-M\shandlekatz\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string17 = /\s\-M\skeepass_discover\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string18 = /\s\-M\slaps\s\-\-kdcHost\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string19 = /\s\-M\sldap\-checker\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string20 = /\s\-M\slsassy\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string21 = /\s\-M\sMAQ\s\-\-kdcHost\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string22 = /\s\-M\smasky\s.*CA\=/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string23 = /\s\-M\sms17\-010\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string24 = /\s\-M\smssql_priv\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string25 = /\s\-M\snanodump\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string26 = /\s\-M\spetitpotam\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string27 = /\s\-M\sprintnightmare\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string28 = /\s\-m\sprivileged\-users\s\-\-full\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string29 = /\s\-M\sprocdump\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string30 = /\s\-M\srunasppl\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string31 = /\s\-M\sshadowcoerce\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string32 = /\s\-M\sspider_plus\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string33 = /\s\-M\steams_localdb\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string34 = /\s\-M\szerologon\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string35 = /\s\-no\-pass\s\-just\-dc\-user\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string36 = /\s\-no\-preauth\s.*\s\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string37 = /\s\-\-only\-abuse\s\-\-dc\-host\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string38 = /\s\-\-password\-not\-required\s\-\-kdcHost\s.*cme/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string39 = /\s\-pfx\s.*\.pfx\s\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string40 = /\s\-request\s\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string41 = /\s\-\-rid\-brute\s2\>\&1\s.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string42 = /\s\-save\-old\s\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string43 = /\sscan\s.*\s\-\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string44 = /\ssmb\s.*\s\-\-dpapi\s.*password/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string45 = /\ssmb\s.*\s\-\-gen\-relay\-list\s.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string46 = /\ssmb\s.*\s\-\-lsa\s\-\-log\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string47 = /\ssmb\s.*\s\-M\smsol\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string48 = /\ssmb\s.*\s\-M\sntlmv1\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string49 = /\ssmb\s.*\s\-\-ntds\s\-\-log\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string50 = /\ssmb\s.*\s\-\-sam\s\-\-log\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string51 = /\suserenum\s.*\s\-\-dc\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string52 = /\s\-vulnerable\s\-stdout\s\-hide\-admins/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string53 = /\$attacker_IPlist/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string54 = /\/asreproast_hashes_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string55 = /\/cme_adcs_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string56 = /\/cme_shares_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string57 = /\/cme_spooler_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string58 = /\/coercer_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string59 = /\/Credentials\/.*\.ccache/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string60 = /\/Credentials\/firefox_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string61 = /\/Credentials\/msol_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string62 = /\/dcsync_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string63 = /\/DomainRecon\/.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string64 = /\/gMSA_dump_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string65 = /\/keepass_discover_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string66 = /\/kerberoast_hashes_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string67 = /\/laps_dump_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string68 = /\/ldeepDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string69 = /\/linWinPwn/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string70 = /\/lsa_dump_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string71 = /\/manspider_output.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string72 = /\/manspiderDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string73 = /\/nmap_smb_scan_all_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string74 = /\/ntds_dump_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string75 = /\/opt\/lwp\-scripts/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string76 = /\/opt\/lwp\-wordlists/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string77 = /\/rockyou\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string78 = /\/sam_dump_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string79 = /\/Scans\/servers_all_smb.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string80 = /\/secretsdump_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string81 = /\/smbmapDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string82 = /\/windapsearch_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string83 = /asrep_attack/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string84 = /asreprc4_attack/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string85 = /asreproast_john_results_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string86 = /asreproast_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string87 = /bhd_enum_dconly/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string88 = /bloodhound_output.*\/dev\/null/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string89 = /bloodhound_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string90 = /bloodhound_output_dconly_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string91 = /certi\.py_vulntemplates_output/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string92 = /certi_py_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string93 = /certipy_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string94 = /certsync_ntds_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string95 = /cirt\-default\-usernames\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string96 = /cme_bloodhound_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string97 = /cme_dfscoerce_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string98 = /cme_get\-desc\-users_pass_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string99 = /cme_get\-desc\-users_pass_results/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string100 = /cme_gpp_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string101 = /cme_ldap\-checker_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string102 = /cme_MachineAccountQuota_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string103 = /cme_ms17\-010_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string104 = /cme_mssql_priv_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string105 = /cme_ntlmv1_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string106 = /cme_passpol_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string107 = /cme_petitpotam_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string108 = /cme_printnightmare_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string109 = /cme_runasppl_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string110 = /cme_shadowcoerce_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string111 = /cme_smb_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string112 = /cme_smbsigning_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string113 = /cme_subnets_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string114 = /cme_trusted\-for\-delegation_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string115 = /cme_users_auth_ldap_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string116 = /cme_users_auth_smb_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string117 = /cme_users_nullsess_smb_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string118 = /cme_webdav_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string119 = /cme_zerologon_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string120 = /coercer_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string121 = /Credentials.*hekatomb_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string122 = /Credentials\/certsync_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string123 = /Credentials\/SAMDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string124 = /deleg_enum_imp/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string125 = /dfscoerce_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string126 = /DomainRecon.*ridbrute/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string127 = /DomainRecon\/ADCS/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string128 = /DomainRecon\/BloodHound/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string129 = /DomainRecon\/SilentHound/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string130 = /donpapi_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string131 = /dpapi_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string132 = /dpapi_dump_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string133 = /enum4linux_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string134 = /finduncshar_scan/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string135 = /gmsa_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string136 = /handlekatz_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string137 = /hekatomb_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string138 = /impacket_findDelegation/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string139 = /impacket_rpcdump_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string140 = /john_crack_asrep/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string141 = /john_crack_kerberoast/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string142 = /juicycreds_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string143 = /\-k\s\-no\-pass\s\-p\s\'\'\s\-\-auth\-method\skerberos/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string144 = /kerberoast_attack/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string145 = /kerberoast_blind_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string146 = /kerberoast_john_results_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string147 = /kerbrute_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string148 = /kerbrute_pass_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string149 = /kerbrute_user_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string150 = /kerbrute_userpass_wordlist_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string151 = /laps_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string152 = /LDAPDomainDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string153 = /ldeep_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string154 = /linWinPwn\-/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string155 = /linWinPwn\./ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string156 = /lsass_dump_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string157 = /lsass_dump_lsassy_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string158 = /lsassy_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string159 = /manspider_scan/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string160 = /masky_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string161 = /ms14\-068_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string162 = /ms17\-010_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string163 = /msol_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string164 = /nanodump_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string165 = /nmap_smb_scan_custom_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string166 = /ntlmv1_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string167 = /Passwords\/Leaked\-Databases.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string168 = /petitpotam_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string169 = /printnightmare_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string170 = /procdump_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string171 = /pwd_dump\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string172 = /ridbrute_attack/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string173 = /rpc:\/\/.*\s\-rpc\-mode\sICPR\s\-icpr\-ca\-name\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string174 = /rpcdump_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string175 = /runasppl_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string176 = /secrets_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string177 = /secrets_dump_dcsync/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string178 = /shadowcoerce_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string179 = /Shares\/cme_spider_plus/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string180 = /Shares\/finduncshar_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string181 = /silenthound_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string182 = /silenthound_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string183 = /smbmapDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string184 = /smbsigning_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string185 = /spooler_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string186 = /targetedkerberoast_attack/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string187 = /targetedkerberoast_hashes_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string188 = /targetedkerberoast_output_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string189 = /\-\-trusted\-for\-delegation\s\-\-kdcHost\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string190 = /user_eq_pass_valid_cme_.*\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string191 = /userpass_cme_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string192 = /userpass_kerbrute_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string193 = /users_list_cme_ldap_nullsess_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string194 = /users_list_kerbrute_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string195 = /users_list_ridbrute_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string196 = /veeam_dump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string197 = /Vulnerabilities\/RPCDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string198 = /windapsearch_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string199 = /xato\-net\-10\-million\-usernames\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string200 = /zerologon_check/ nocase ascii wide

    condition:
        any of them
}