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
        $string1 = " aad3b435b51404eeaad3b435b51404ee"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string2 = " --asreproast "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string3 = /\scoerce\s.{0,1000}\s\-\-dc\-ip\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string4 = /\s\-\-dc\s.{0,1000}\s\-m\scustom\s\-\-filter\s.{0,1000}objectCategory/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string5 = /\s\-dc\-ip\s.{0,1000}\s\-dump\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string6 = /\s\-\-dc\-ip\s.{0,1000}\s\-\-vuln\s\-\-enabled/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string7 = /\s\-dc\-ip\s.{0,1000}SAMDump/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string8 = " --force-kerb "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string9 = /\s\-\-format\=krb5asrep.{0,1000}\s\-\-wordlist\=/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string10 = " -g -n --kerberoast"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string11 = " --impersonate Administrator -shell "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string12 = /\s\-ip\s.{0,1000}\s\-smb2support\s.{0,1000}lwpshare.{0,1000}\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string13 = /\sldap\s.{0,1000}\s\-\-gmsa\s.{0,1000}dump/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string14 = " linWinPwn"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string15 = " -M dfscoerce "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string16 = " -M handlekatz "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string17 = " -M keepass_discover "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string18 = " -M laps --kdcHost "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string19 = " -M ldap-checker "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string20 = " -M lsassy "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string21 = " -M MAQ --kdcHost "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string22 = /\s\-M\smasky\s.{0,1000}CA\=/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string23 = " -M ms17-010 "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string24 = " -M mssql_priv "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string25 = " -M nanodump "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string26 = " -M petitpotam "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string27 = " -M printnightmare "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string28 = " -m privileged-users --full "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string29 = " -M procdump "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string30 = " -M runasppl "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string31 = " -M shadowcoerce "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string32 = " -M spider_plus "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string33 = " -M teams_localdb "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string34 = " -M zerologon "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string35 = " -no-pass -just-dc-user "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string36 = /\s\-no\-preauth\s.{0,1000}\s\-dc\-ip\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string37 = " --only-abuse --dc-host "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string38 = /\s\-\-password\-not\-required\s\-\-kdcHost\s.{0,1000}cme/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string39 = /\s\-pfx\s.{0,1000}\.pfx\s\-dc\-ip\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string40 = " -request -dc-ip "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string41 = /\s\-\-rid\-brute\s2\>\&1\s.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string42 = " -save-old -dc-ip "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string43 = /\sscan\s.{0,1000}\s\-\-dc\-ip\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string44 = /\ssmb\s.{0,1000}\s\-\-dpapi\s.{0,1000}password/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string45 = /\ssmb\s.{0,1000}\s\-\-gen\-relay\-list\s.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string46 = /\ssmb\s.{0,1000}\s\-\-lsa\s\-\-log\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string47 = /\ssmb\s.{0,1000}\s\-M\smsol\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string48 = /\ssmb\s.{0,1000}\s\-M\sntlmv1\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string49 = /\ssmb\s.{0,1000}\s\-\-ntds\s\-\-log\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string50 = /\ssmb\s.{0,1000}\s\-\-sam\s\-\-log\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string51 = /\suserenum\s.{0,1000}\s\-\-dc\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string52 = " -vulnerable -stdout -hide-admins"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string53 = /\$attacker_IPlist/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string54 = /\/asreproast_hashes_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string55 = /\/cme_adcs_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string56 = "/cme_shares_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string57 = "/cme_spooler_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string58 = /\/coercer_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string59 = /\/Credentials\/.{0,1000}\.ccache/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string60 = /\/Credentials\/firefox_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string61 = /\/Credentials\/msol_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string62 = /\/dcsync_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string63 = /\/DomainRecon\/.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string64 = /\/gMSA_dump_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string65 = /\/keepass_discover_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string66 = /\/kerberoast_hashes_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string67 = /\/laps_dump_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string68 = "/ldeepDump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string69 = "/linWinPwn"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string70 = /\/lsa_dump_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string71 = /\/manspider_output.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string72 = "/manspiderDump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string73 = /\/nmap_smb_scan_all_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string74 = /\/ntds_dump_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string75 = "/opt/lwp-scripts"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string76 = "/opt/lwp-wordlists"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string77 = /\/rockyou\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string78 = /\/sam_dump_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string79 = /\/Scans\/servers_all_smb.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string80 = /\/secretsdump_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string81 = "/smbmapDump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string82 = /\/windapsearch_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string83 = "asrep_attack"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string84 = "asreprc4_attack"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string85 = "asreproast_john_results_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string86 = /asreproast_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string87 = "bhd_enum_dconly"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string88 = /bloodhound_output.{0,1000}\/dev\/null/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string89 = /bloodhound_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string90 = "bloodhound_output_dconly_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string91 = /certi\.py_vulntemplates_output/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string92 = "certi_py_enum"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string93 = "certipy_enum"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string94 = "certsync_ntds_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string95 = /cirt\-default\-usernames\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string96 = /cme_bloodhound_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string97 = /cme_dfscoerce_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string98 = "cme_get-desc-users_pass_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string99 = "cme_get-desc-users_pass_results"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string100 = /cme_gpp_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string101 = "cme_ldap-checker_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string102 = "cme_MachineAccountQuota_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string103 = "cme_ms17-010_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string104 = /cme_mssql_priv_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string105 = "cme_ntlmv1_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string106 = /cme_passpol_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string107 = /cme_petitpotam_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string108 = /cme_printnightmare_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string109 = /cme_runasppl_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string110 = /cme_shadowcoerce_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string111 = "cme_smb_enum"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string112 = /cme_smbsigning_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string113 = /cme_subnets_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string114 = "cme_trusted-for-delegation_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string115 = /cme_users_auth_ldap_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string116 = /cme_users_auth_smb_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string117 = /cme_users_nullsess_smb_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string118 = /cme_webdav_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string119 = /cme_zerologon_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string120 = "coercer_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string121 = /Credentials.{0,1000}hekatomb_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string122 = "Credentials/certsync_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string123 = "Credentials/SAMDump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string124 = "deleg_enum_imp"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string125 = "dfscoerce_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string126 = /DomainRecon.{0,1000}ridbrute/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string127 = "DomainRecon/ADCS"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string128 = "DomainRecon/BloodHound"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string129 = "DomainRecon/SilentHound"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string130 = "donpapi_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string131 = "dpapi_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string132 = /dpapi_dump_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string133 = /enum4linux_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string134 = "finduncshar_scan"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string135 = "gmsa_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string136 = "handlekatz_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string137 = "hekatomb_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string138 = "impacket_findDelegation"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string139 = "impacket_rpcdump_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string140 = "john_crack_asrep"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string141 = "john_crack_kerberoast"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string142 = "juicycreds_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string143 = "-k -no-pass -p '' --auth-method kerberos"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string144 = "kerberoast_attack"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string145 = "kerberoast_blind_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string146 = "kerberoast_john_results_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string147 = "kerbrute_enum"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string148 = "kerbrute_pass_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string149 = "kerbrute_user_output_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string150 = "kerbrute_userpass_wordlist_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string151 = "laps_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string152 = "LDAPDomainDump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string153 = "ldeep_enum"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string154 = "linWinPwn-"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string155 = /linWinPwn\./
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string156 = "lsass_dump_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string157 = "lsass_dump_lsassy_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string158 = "lsassy_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string159 = "manspider_scan"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string160 = "masky_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string161 = "ms14-068_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string162 = "ms17-010_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string163 = "msol_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string164 = "nanodump_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string165 = /nmap_smb_scan_custom_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string166 = "ntlmv1_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string167 = /Passwords\/Leaked\-Databases.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string168 = "petitpotam_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string169 = "printnightmare_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string170 = "procdump_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string171 = "pwd_dump "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string172 = "ridbrute_attack"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string173 = /rpc\:\/\/.{0,1000}\s\-rpc\-mode\sICPR\s\-icpr\-ca\-name\s/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string174 = "rpcdump_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string175 = "runasppl_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string176 = "secrets_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string177 = "secrets_dump_dcsync"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string178 = "shadowcoerce_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string179 = "Shares/cme_spider_plus"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string180 = /Shares\/finduncshar_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string181 = "silenthound_enum"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string182 = /silenthound_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string183 = "smbmapDump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string184 = "smbsigning_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string185 = "spooler_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string186 = "targetedkerberoast_attack"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string187 = /targetedkerberoast_hashes_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string188 = /targetedkerberoast_output_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string189 = "--trusted-for-delegation --kdcHost "
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string190 = /user_eq_pass_valid_cme_.{0,1000}\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string191 = "userpass_cme_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string192 = "userpass_kerbrute_check"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string193 = "users_list_cme_ldap_nullsess_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string194 = "users_list_kerbrute_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string195 = "users_list_ridbrute_"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string196 = "veeam_dump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string197 = "Vulnerabilities/RPCDump"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string198 = "windapsearch_enum"
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string199 = /xato\-net\-10\-million\-usernames\.txt/
        // Description: linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks
        // Reference: https://github.com/lefayjey/linWinPwn
        $string200 = "zerologon_check"

    condition:
        any of them
}
