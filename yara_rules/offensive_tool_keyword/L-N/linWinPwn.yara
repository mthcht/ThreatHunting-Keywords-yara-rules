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
        $string1 = /.{0,1000}\saad3b435b51404eeaad3b435b51404ee.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string2 = /.{0,1000}\s\-\-asreproast\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string3 = /.{0,1000}\scoerce\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string4 = /.{0,1000}\s\-\-dc\s.{0,1000}\s\-m\scustom\s\-\-filter\s.{0,1000}objectCategory.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string5 = /.{0,1000}\s\-dc\-ip\s.{0,1000}\s\-dump\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string6 = /.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-\-vuln\s\-\-enabled.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string7 = /.{0,1000}\s\-dc\-ip\s.{0,1000}SAMDump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string8 = /.{0,1000}\s\-\-force\-kerb\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string9 = /.{0,1000}\s\-\-format\=krb5asrep.{0,1000}\s\-\-wordlist\=.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string10 = /.{0,1000}\s\-g\s\-n\s\-\-kerberoast.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string11 = /.{0,1000}\s\-\-impersonate\sAdministrator\s\-shell\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string12 = /.{0,1000}\s\-ip\s.{0,1000}\s\-smb2support\s.{0,1000}lwpshare.{0,1000}\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string13 = /.{0,1000}\sldap\s.{0,1000}\s\-\-gmsa\s.{0,1000}dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string14 = /.{0,1000}\slinWinPwn.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string15 = /.{0,1000}\s\-M\sdfscoerce\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string16 = /.{0,1000}\s\-M\shandlekatz\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string17 = /.{0,1000}\s\-M\skeepass_discover\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string18 = /.{0,1000}\s\-M\slaps\s\-\-kdcHost\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string19 = /.{0,1000}\s\-M\sldap\-checker\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string20 = /.{0,1000}\s\-M\slsassy\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string21 = /.{0,1000}\s\-M\sMAQ\s\-\-kdcHost\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string22 = /.{0,1000}\s\-M\smasky\s.{0,1000}CA\=.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string23 = /.{0,1000}\s\-M\sms17\-010\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string24 = /.{0,1000}\s\-M\smssql_priv\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string25 = /.{0,1000}\s\-M\snanodump\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string26 = /.{0,1000}\s\-M\spetitpotam\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string27 = /.{0,1000}\s\-M\sprintnightmare\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string28 = /.{0,1000}\s\-m\sprivileged\-users\s\-\-full\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string29 = /.{0,1000}\s\-M\sprocdump\s/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string30 = /.{0,1000}\s\-M\srunasppl\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string31 = /.{0,1000}\s\-M\sshadowcoerce\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string32 = /.{0,1000}\s\-M\sspider_plus\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string33 = /.{0,1000}\s\-M\steams_localdb\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string34 = /.{0,1000}\s\-M\szerologon\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string35 = /.{0,1000}\s\-no\-pass\s\-just\-dc\-user\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string36 = /.{0,1000}\s\-no\-preauth\s.{0,1000}\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string37 = /.{0,1000}\s\-\-only\-abuse\s\-\-dc\-host\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string38 = /.{0,1000}\s\-\-password\-not\-required\s\-\-kdcHost\s.{0,1000}cme.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string39 = /.{0,1000}\s\-pfx\s.{0,1000}\.pfx\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string40 = /.{0,1000}\s\-request\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string41 = /.{0,1000}\s\-\-rid\-brute\s2\>\&1\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string42 = /.{0,1000}\s\-save\-old\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string43 = /.{0,1000}\sscan\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string44 = /.{0,1000}\ssmb\s.{0,1000}\s\-\-dpapi\s.{0,1000}password.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string45 = /.{0,1000}\ssmb\s.{0,1000}\s\-\-gen\-relay\-list\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string46 = /.{0,1000}\ssmb\s.{0,1000}\s\-\-lsa\s\-\-log\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string47 = /.{0,1000}\ssmb\s.{0,1000}\s\-M\smsol\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string48 = /.{0,1000}\ssmb\s.{0,1000}\s\-M\sntlmv1\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string49 = /.{0,1000}\ssmb\s.{0,1000}\s\-\-ntds\s\-\-log\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string50 = /.{0,1000}\ssmb\s.{0,1000}\s\-\-sam\s\-\-log\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string51 = /.{0,1000}\suserenum\s.{0,1000}\s\-\-dc\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string52 = /.{0,1000}\s\-vulnerable\s\-stdout\s\-hide\-admins.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string53 = /.{0,1000}\$attacker_IPlist.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string54 = /.{0,1000}\/asreproast_hashes_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string55 = /.{0,1000}\/cme_adcs_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string56 = /.{0,1000}\/cme_shares_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string57 = /.{0,1000}\/cme_spooler_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string58 = /.{0,1000}\/coercer_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string59 = /.{0,1000}\/Credentials\/.{0,1000}\.ccache.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string60 = /.{0,1000}\/Credentials\/firefox_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string61 = /.{0,1000}\/Credentials\/msol_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string62 = /.{0,1000}\/dcsync_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string63 = /.{0,1000}\/DomainRecon\/.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string64 = /.{0,1000}\/gMSA_dump_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string65 = /.{0,1000}\/keepass_discover_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string66 = /.{0,1000}\/kerberoast_hashes_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string67 = /.{0,1000}\/laps_dump_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string68 = /.{0,1000}\/ldeepDump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string69 = /.{0,1000}\/linWinPwn.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string70 = /.{0,1000}\/lsa_dump_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string71 = /.{0,1000}\/manspider_output.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string72 = /.{0,1000}\/manspiderDump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string73 = /.{0,1000}\/nmap_smb_scan_all_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string74 = /.{0,1000}\/ntds_dump_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string75 = /.{0,1000}\/opt\/lwp\-scripts.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string76 = /.{0,1000}\/opt\/lwp\-wordlists.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string77 = /.{0,1000}\/rockyou\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string78 = /.{0,1000}\/sam_dump_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string79 = /.{0,1000}\/Scans\/servers_all_smb.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string80 = /.{0,1000}\/secretsdump_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string81 = /.{0,1000}\/smbmapDump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string82 = /.{0,1000}\/windapsearch_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string83 = /.{0,1000}asrep_attack.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string84 = /.{0,1000}asreprc4_attack.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string85 = /.{0,1000}asreproast_john_results_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string86 = /.{0,1000}asreproast_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string87 = /.{0,1000}bhd_enum_dconly.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string88 = /.{0,1000}bloodhound_output.{0,1000}\/dev\/null.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string89 = /.{0,1000}bloodhound_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string90 = /.{0,1000}bloodhound_output_dconly_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string91 = /.{0,1000}certi\.py_vulntemplates_output.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string92 = /.{0,1000}certi_py_enum.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string93 = /.{0,1000}certipy_enum.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string94 = /.{0,1000}certsync_ntds_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string95 = /.{0,1000}cirt\-default\-usernames\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string96 = /.{0,1000}cme_bloodhound_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string97 = /.{0,1000}cme_dfscoerce_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string98 = /.{0,1000}cme_get\-desc\-users_pass_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string99 = /.{0,1000}cme_get\-desc\-users_pass_results.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string100 = /.{0,1000}cme_gpp_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string101 = /.{0,1000}cme_ldap\-checker_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string102 = /.{0,1000}cme_MachineAccountQuota_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string103 = /.{0,1000}cme_ms17\-010_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string104 = /.{0,1000}cme_mssql_priv_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string105 = /.{0,1000}cme_ntlmv1_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string106 = /.{0,1000}cme_passpol_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string107 = /.{0,1000}cme_petitpotam_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string108 = /.{0,1000}cme_printnightmare_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string109 = /.{0,1000}cme_runasppl_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string110 = /.{0,1000}cme_shadowcoerce_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string111 = /.{0,1000}cme_smb_enum.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string112 = /.{0,1000}cme_smbsigning_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string113 = /.{0,1000}cme_subnets_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string114 = /.{0,1000}cme_trusted\-for\-delegation_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string115 = /.{0,1000}cme_users_auth_ldap_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string116 = /.{0,1000}cme_users_auth_smb_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string117 = /.{0,1000}cme_users_nullsess_smb_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string118 = /.{0,1000}cme_webdav_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string119 = /.{0,1000}cme_zerologon_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string120 = /.{0,1000}coercer_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string121 = /.{0,1000}Credentials.{0,1000}hekatomb_.{0,1000}\.txt/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string122 = /.{0,1000}Credentials\/certsync_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string123 = /.{0,1000}Credentials\/SAMDump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string124 = /.{0,1000}deleg_enum_imp.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string125 = /.{0,1000}dfscoerce_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string126 = /.{0,1000}DomainRecon.{0,1000}ridbrute.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string127 = /.{0,1000}DomainRecon\/ADCS.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string128 = /.{0,1000}DomainRecon\/BloodHound.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string129 = /.{0,1000}DomainRecon\/SilentHound.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string130 = /.{0,1000}donpapi_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string131 = /.{0,1000}dpapi_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string132 = /.{0,1000}dpapi_dump_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string133 = /.{0,1000}enum4linux_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string134 = /.{0,1000}finduncshar_scan.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string135 = /.{0,1000}gmsa_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string136 = /.{0,1000}handlekatz_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string137 = /.{0,1000}hekatomb_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string138 = /.{0,1000}impacket_findDelegation.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string139 = /.{0,1000}impacket_rpcdump_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string140 = /.{0,1000}john_crack_asrep.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string141 = /.{0,1000}john_crack_kerberoast.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string142 = /.{0,1000}juicycreds_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string143 = /.{0,1000}\-k\s\-no\-pass\s\-p\s\'\'\s\-\-auth\-method\skerberos.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string144 = /.{0,1000}kerberoast_attack.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string145 = /.{0,1000}kerberoast_blind_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string146 = /.{0,1000}kerberoast_john_results_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string147 = /.{0,1000}kerbrute_enum.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string148 = /.{0,1000}kerbrute_pass_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string149 = /.{0,1000}kerbrute_user_output_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string150 = /.{0,1000}kerbrute_userpass_wordlist_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string151 = /.{0,1000}laps_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string152 = /.{0,1000}LDAPDomainDump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string153 = /.{0,1000}ldeep_enum.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string154 = /.{0,1000}linWinPwn\-.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string155 = /.{0,1000}linWinPwn\..{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string156 = /.{0,1000}lsass_dump_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string157 = /.{0,1000}lsass_dump_lsassy_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string158 = /.{0,1000}lsassy_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string159 = /.{0,1000}manspider_scan.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string160 = /.{0,1000}masky_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string161 = /.{0,1000}ms14\-068_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string162 = /.{0,1000}ms17\-010_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string163 = /.{0,1000}msol_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string164 = /.{0,1000}nanodump_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string165 = /.{0,1000}nmap_smb_scan_custom_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string166 = /.{0,1000}ntlmv1_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string167 = /.{0,1000}Passwords\/Leaked\-Databases.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string168 = /.{0,1000}petitpotam_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string169 = /.{0,1000}printnightmare_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string170 = /.{0,1000}procdump_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string171 = /.{0,1000}pwd_dump\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string172 = /.{0,1000}ridbrute_attack.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string173 = /.{0,1000}rpc:\/\/.{0,1000}\s\-rpc\-mode\sICPR\s\-icpr\-ca\-name\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string174 = /.{0,1000}rpcdump_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string175 = /.{0,1000}runasppl_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string176 = /.{0,1000}secrets_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string177 = /.{0,1000}secrets_dump_dcsync.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string178 = /.{0,1000}shadowcoerce_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string179 = /.{0,1000}Shares\/cme_spider_plus.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string180 = /.{0,1000}Shares\/finduncshar_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string181 = /.{0,1000}silenthound_enum.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string182 = /.{0,1000}silenthound_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string183 = /.{0,1000}smbmapDump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string184 = /.{0,1000}smbsigning_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string185 = /.{0,1000}spooler_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string186 = /.{0,1000}targetedkerberoast_attack.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string187 = /.{0,1000}targetedkerberoast_hashes_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string188 = /.{0,1000}targetedkerberoast_output_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string189 = /.{0,1000}\-\-trusted\-for\-delegation\s\-\-kdcHost\s.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string190 = /.{0,1000}user_eq_pass_valid_cme_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string191 = /.{0,1000}userpass_cme_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string192 = /.{0,1000}userpass_kerbrute_check.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string193 = /.{0,1000}users_list_cme_ldap_nullsess_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string194 = /.{0,1000}users_list_kerbrute_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string195 = /.{0,1000}users_list_ridbrute_.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string196 = /.{0,1000}veeam_dump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string197 = /.{0,1000}Vulnerabilities\/RPCDump.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string198 = /.{0,1000}windapsearch_enum.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string199 = /.{0,1000}xato\-net\-10\-million\-usernames\.txt.{0,1000}/ nocase ascii wide
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string200 = /.{0,1000}zerologon_check.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
