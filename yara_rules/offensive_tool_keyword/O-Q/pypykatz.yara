rule pypykatz
{
    meta:
        description = "Detection patterns for the tool 'pypykatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pypykatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string1 = /.{0,1000}\sdpapi\sblob\s.{0,1000}\.json\s.{0,1000}\.dat.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string2 = /.{0,1000}\sdpapi\scredential\s.{0,1000}\.json\scred.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string3 = /.{0,1000}\sdpapi\smasterkey\s\/root\/.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string4 = /.{0,1000}\sdpapi\sminidump\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string5 = /.{0,1000}\sdpapi\sprekey\snt\s.{0,1000}S\-1\-5\-21.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string6 = /.{0,1000}\sdpapi\sprekey\spassword\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string7 = /.{0,1000}\sdpapi\sprekey\sregistry\s.{0,1000}\.reg.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string8 = /.{0,1000}\sdpapi\ssecurestring\s.{0,1000}\.dat.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string9 = /.{0,1000}\skerberos\sasreproast\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string10 = /.{0,1000}\skerberos\sbrute\s.{0,1000}\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string11 = /.{0,1000}\skerberos\sbrute\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string12 = /.{0,1000}\skerberos\sccache\sdel\s.{0,1000}\.ccache.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string13 = /.{0,1000}\skerberos\sccache\sexportkirbi\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string14 = /.{0,1000}\skerberos\sccache\slist\s.{0,1000}\.ccache.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string15 = /.{0,1000}\skerberos\sccache\sloadkirbi\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string16 = /.{0,1000}\skerberos\sccache\sroast\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string17 = /.{0,1000}\skerberos\skeytab\s.{0,1000}\.keytab.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string18 = /.{0,1000}\skerberos\skirbi\sparse\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string19 = /.{0,1000}\skerberos\sspnroast\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string20 = /.{0,1000}\slive\sdpapi\sblobfile\s.{0,1000}\.blob.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string21 = /.{0,1000}\slive\sdpapi\scred\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string22 = /.{0,1000}\slive\sdpapi\skeys\s\-o\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string23 = /.{0,1000}\slive\sdpapi\ssecurestring\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string24 = /.{0,1000}\slive\sdpapi\svcred\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string25 = /.{0,1000}\slive\sdpapi\svpol\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string26 = /.{0,1000}\slive\sdpapi\swifi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string27 = /.{0,1000}\slive\skerberos\sapreq\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string28 = /.{0,1000}\slive\skerberos\sdump.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string29 = /.{0,1000}\slive\skerberos\spurge.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string30 = /.{0,1000}\slive\skerberos\sroast.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string31 = /.{0,1000}\slive\skerberos\ssessions.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string32 = /.{0,1000}\slive\skerberos\stgt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string33 = /.{0,1000}\slive\skerberos\striage.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string34 = /.{0,1000}\slive\slsa\s\-o\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string35 = /.{0,1000}\slive\slsa\s\-o\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string36 = /.{0,1000}\slive\sprocess\screate\s\-c\sregedit.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string37 = /.{0,1000}\slive\ssmb\sclient\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string38 = /.{0,1000}\slive\ssmb\sdcsync\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string39 = /.{0,1000}\slive\ssmb\slsassdump\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string40 = /.{0,1000}\slive\ssmb\sregdump\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string41 = /.{0,1000}\slive\ssmb\ssecretsdump\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string42 = /.{0,1000}\slive\ssmbapi\slocalgroup\senum\s\-t.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string43 = /.{0,1000}\slive\ssmbapi\ssession\senum\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string44 = /.{0,1000}\slive\ssmbapi\sshare\senum.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string45 = /.{0,1000}\slive\susers\swhoami.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string46 = /.{0,1000}\slsa\sminidump\s.{0,1000}\s\-o\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string47 = /.{0,1000}\slsa\sminidump\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string48 = /.{0,1000}\slsa\sminidump\s\/.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string49 = /.{0,1000}\ssmb\sclient\s.{0,1000}\sshares\s.{0,1000}use\sc\$.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string50 = /.{0,1000}\ssmb\sshareenum\s.{0,1000}smb2\+ntlm\-password.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string51 = /.{0,1000}\.py\s\srekall\s.{0,1000}\.dmp.{0,1000}\s\-t\s0/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string52 = /.{0,1000}\/kerberosticket\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string53 = /.{0,1000}\/lsass\.DMP.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string54 = /.{0,1000}\/pypykatz.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string55 = /.{0,1000}\/ssp\/decryptor\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string56 = /.{0,1000}\\\\c\$\\Windows\\Temp\\.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string57 = /.{0,1000}\\lsass\.DMP/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string58 = /.{0,1000}\\x44\\x8b\\x01\\x44\\x39\\x42.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string59 = /.{0,1000}\\x83\\x64\\x24\\x30\\x00\\x48\\x8d\\x45\\xe0\\x44\\x8b\\x4d\\xd8\\x48\\x8d\\x15.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string60 = /.{0,1000}\\x8b\\x31\\x39\\x72\\x10\\x75.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string61 = /.{0,1000}_dcsync\.txt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string62 = /.{0,1000}_lsass\.txt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string63 = /.{0,1000}_lsassdecrypt\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string64 = /.{0,1000}apypykatz\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string65 = /.{0,1000}asreproast_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string66 = /.{0,1000}dcsync\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string67 = /.{0,1000}dpapi\/decryptor\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string68 = /.{0,1000}get_masterkeys_from_lsass.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string69 = /.{0,1000}gppassword\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string70 = /.{0,1000}import\sapypykatz.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string71 = /.{0,1000}import\spypykatz.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string72 = /.{0,1000}info\@skelsecprojects\.com.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string73 = /.{0,1000}install\spypykatz.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string74 = /.{0,1000}KatzSystemArchitecture.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string75 = /.{0,1000}kerberos\/decryptor\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string76 = /.{0,1000}KIWI_CLOUDAP_LOGON_LIST_ENTRY_21H2.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string77 = /.{0,1000}lsa_decryptor\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string78 = /.{0,1000}lsa_decryptor_nt.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string79 = /.{0,1000}LSASecretDefaultPassword.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string80 = /.{0,1000}minidump.{0,1000}minikerberos.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string81 = /.{0,1000}pypykatz\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string82 = /.{0,1000}pypykatz\.commons.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string83 = /.{0,1000}pypykatz\.dpapi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string84 = /.{0,1000}pypykatz\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string85 = /.{0,1000}pypykatz\.git.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string86 = /.{0,1000}pypykatz\.kerberos.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string87 = /.{0,1000}pypykatz\.lsadecryptor.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string88 = /.{0,1000}pypykatz\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string89 = /.{0,1000}pypykatz\.registry.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string90 = /.{0,1000}pypykatz_rekall\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string91 = /.{0,1000}pypykatz\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string92 = /.{0,1000}rekallreader\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string93 = /.{0,1000}shareenum\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string94 = /.{0,1000}spnroast_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string95 = /.{0,1000}tasklist\s\/fi\s.{0,1000}Imagename\seq\slsass\.exe.{0,1000}\s\|\sfind\s.{0,1000}lsass.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string96 = /.{0,1000}tspkg\/decryptor\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string97 = /.{0,1000}wdigest\/decryptor\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
