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
        $string3 = /\scoerce\s.{0,1000}\s\-\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string4 = /\s\-\-dc\s.{0,1000}\s\-m\scustom\s\-\-filter\s.{0,1000}objectCategory/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string5 = /\s\-dc\-ip\s.{0,1000}\s\-dump\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string6 = /\s\-\-dc\-ip\s.{0,1000}\s\-\-vuln\s\-\-enabled/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string7 = /\s\-dc\-ip\s.{0,1000}SAMDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string8 = /\s\-\-force\-kerb\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string9 = /\s\-\-format\=krb5asrep.{0,1000}\s\-\-wordlist\=/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string10 = /\s\-g\s\-n\s\-\-kerberoast/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string11 = /\s\-\-impersonate\sAdministrator\s\-shell\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string12 = /\s\-ip\s.{0,1000}\s\-smb2support\s.{0,1000}lwpshare.{0,1000}\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string13 = /\sldap\s.{0,1000}\s\-\-gmsa\s.{0,1000}dump/ nocase ascii wide
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
        $string22 = /\s\-M\smasky\s.{0,1000}CA\=/ nocase ascii wide
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
        $string36 = /\s\-no\-preauth\s.{0,1000}\s\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string37 = /\s\-\-only\-abuse\s\-\-dc\-host\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string38 = /\s\-\-password\-not\-required\s\-\-kdcHost\s.{0,1000}cme/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string39 = /\s\-pfx\s.{0,1000}\.pfx\s\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string40 = /\s\-request\s\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string41 = /\s\-\-rid\-brute\s2\>\&1\s.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string42 = /\s\-save\-old\s\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string43 = /\sscan\s.{0,1000}\s\-\-dc\-ip\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string44 = /\ssmb\s.{0,1000}\s\-\-dpapi\s.{0,1000}password/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string45 = /\ssmb\s.{0,1000}\s\-\-gen\-relay\-list\s.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string46 = /\ssmb\s.{0,1000}\s\-\-lsa\s\-\-log\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string47 = /\ssmb\s.{0,1000}\s\-M\smsol\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string48 = /\ssmb\s.{0,1000}\s\-M\sntlmv1\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string49 = /\ssmb\s.{0,1000}\s\-\-ntds\s\-\-log\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string50 = /\ssmb\s.{0,1000}\s\-\-sam\s\-\-log\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string51 = /\suserenum\s.{0,1000}\s\-\-dc\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string52 = /\s\-vulnerable\s\-stdout\s\-hide\-admins/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string53 = /\$attacker_IPlist/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string54 = /\/asreproast_hashes_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string55 = /\/cme_adcs_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string56 = /\/cme_shares_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string57 = /\/cme_spooler_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string58 = /\/coercer_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string59 = /\/Credentials\/.{0,1000}\.ccache/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string60 = /\/Credentials\/firefox_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string61 = /\/Credentials\/msol_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string62 = /\/dcsync_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string63 = /\/DomainRecon\/.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string64 = /\/gMSA_dump_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string65 = /\/keepass_discover_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string66 = /\/kerberoast_hashes_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string67 = /\/laps_dump_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string68 = /\/ldeepDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string69 = /\/linWinPwn/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string70 = /\/lsa_dump_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string71 = /\/manspider_output.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string72 = /\/manspiderDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string73 = /\/nmap_smb_scan_all_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string74 = /\/ntds_dump_.{0,1000}\.txt/ nocase ascii wide
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
        $string78 = /\/sam_dump_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string79 = /\/Scans\/servers_all_smb.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string80 = /\/secretsdump_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string81 = /\/smbmapDump/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string82 = /\/windapsearch_.{0,1000}\.txt/ nocase ascii wide
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
        $string86 = /asreproast_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string87 = /bhd_enum_dconly/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string88 = /bloodhound_output.{0,1000}\/dev\/null/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string89 = /bloodhound_output_.{0,1000}\.txt/ nocase ascii wide
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
        $string96 = /cme_bloodhound_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string97 = /cme_dfscoerce_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string98 = /cme_get\-desc\-users_pass_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string99 = /cme_get\-desc\-users_pass_results/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string100 = /cme_gpp_output_.{0,1000}\.txt/ nocase ascii wide
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
        $string104 = /cme_mssql_priv_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string105 = /cme_ntlmv1_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string106 = /cme_passpol_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string107 = /cme_petitpotam_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string108 = /cme_printnightmare_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string109 = /cme_runasppl_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string110 = /cme_shadowcoerce_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string111 = /cme_smb_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string112 = /cme_smbsigning_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string113 = /cme_subnets_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string114 = /cme_trusted\-for\-delegation_output_/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string115 = /cme_users_auth_ldap_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string116 = /cme_users_auth_smb_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string117 = /cme_users_nullsess_smb_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string118 = /cme_webdav_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string119 = /cme_zerologon_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string120 = /coercer_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string121 = /Credentials.{0,1000}hekatomb_.{0,1000}\.txt/ nocase ascii wide
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
        $string126 = /DomainRecon.{0,1000}ridbrute/ nocase ascii wide
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
        $string132 = /dpapi_dump_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string133 = /enum4linux_.{0,1000}\.txt/ nocase ascii wide
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
        $string165 = /nmap_smb_scan_custom_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string166 = /ntlmv1_check/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string167 = /Passwords\/Leaked\-Databases.{0,1000}\.txt/ nocase ascii wide
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
        $string173 = /rpc\:\/\/.{0,1000}\s\-rpc\-mode\sICPR\s\-icpr\-ca\-name\s/ nocase ascii wide
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
        $string180 = /Shares\/finduncshar_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string181 = /silenthound_enum/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string182 = /silenthound_output_.{0,1000}\.txt/ nocase ascii wide
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
        $string187 = /targetedkerberoast_hashes_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string188 = /targetedkerberoast_output_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string189 = /\-\-trusted\-for\-delegation\s\-\-kdcHost\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string190 = /user_eq_pass_valid_cme_.{0,1000}\.txt/ nocase ascii wide
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
