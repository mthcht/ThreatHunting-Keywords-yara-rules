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
        $string1 = /\sdpapi\sblob\s.{0,1000}\.json\s.{0,1000}\.dat/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string2 = /\sdpapi\scredential\s.{0,1000}\.json\scred/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string3 = /\sdpapi\smasterkey\s\/root\// nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string4 = /\sdpapi\sminidump\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string5 = /\sdpapi\sprekey\snt\s.{0,1000}S\-1\-5\-21/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string6 = /\sdpapi\sprekey\spassword\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string7 = /\sdpapi\sprekey\sregistry\s.{0,1000}\.reg/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string8 = /\sdpapi\ssecurestring\s.{0,1000}\.dat/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string9 = /\skerberos\sasreproast\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string10 = /\skerberos\sbrute\s.{0,1000}\s\-d\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string11 = /\skerberos\sbrute\s.{0,1000}\.txt/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string12 = /\skerberos\sccache\sdel\s.{0,1000}\.ccache/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string13 = /\skerberos\sccache\sexportkirbi\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string14 = /\skerberos\sccache\slist\s.{0,1000}\.ccache/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string15 = /\skerberos\sccache\sloadkirbi\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string16 = /\skerberos\sccache\sroast\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string17 = /\skerberos\skeytab\s.{0,1000}\.keytab/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string18 = /\skerberos\skirbi\sparse\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string19 = /\skerberos\sspnroast\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string20 = /\slive\sdpapi\sblobfile\s.{0,1000}\.blob/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string21 = /\slive\sdpapi\scred\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string22 = /\slive\sdpapi\skeys\s\-o\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string23 = /\slive\sdpapi\ssecurestring\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string24 = /\slive\sdpapi\svcred\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string25 = /\slive\sdpapi\svpol\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string26 = /\slive\sdpapi\swifi/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string27 = /\slive\skerberos\sapreq\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string28 = /\slive\skerberos\sdump/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string29 = /\slive\skerberos\spurge/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string30 = /\slive\skerberos\sroast/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string31 = /\slive\skerberos\ssessions/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string32 = /\slive\skerberos\stgt/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string33 = /\slive\skerberos\striage/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string34 = /\slive\slsa\s\-o\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string35 = /\slive\slsa\s\-o\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string36 = /\slive\sprocess\screate\s\-c\sregedit/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string37 = /\slive\ssmb\sclient\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string38 = /\slive\ssmb\sdcsync\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string39 = /\slive\ssmb\slsassdump\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string40 = /\slive\ssmb\sregdump\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string41 = /\slive\ssmb\ssecretsdump\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string42 = /\slive\ssmbapi\slocalgroup\senum\s\-t/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string43 = /\slive\ssmbapi\ssession\senum\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string44 = /\slive\ssmbapi\sshare\senum/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string45 = /\slive\susers\swhoami/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string46 = /\slsa\sminidump\s.{0,1000}\s\-o\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string47 = /\slsa\sminidump\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string48 = /\slsa\sminidump\s\// nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string49 = /\ssmb\sclient\s.{0,1000}\sshares\s.{0,1000}use\sc\$/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string50 = /\ssmb\sshareenum\s.{0,1000}smb2\+ntlm\-password/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string51 = /\.py\s\srekall\s.{0,1000}\.dmp.{0,1000}\s\-t\s0/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string52 = /\/kerberosticket\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string53 = /\/lsass\.DMP/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string54 = /\/pypykatz/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string55 = /\/ssp\/decryptor\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string56 = /\\\\c\$\\Windows\\Temp\\.{0,1000}\.dmp/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string57 = /\\lsass\.DMP/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string58 = /\\x44\\x8b\\x01\\x44\\x39\\x42/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string59 = /\\x83\\x64\\x24\\x30\\x00\\x48\\x8d\\x45\\xe0\\x44\\x8b\\x4d\\xd8\\x48\\x8d\\x15/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string60 = /\\x8b\\x31\\x39\\x72\\x10\\x75/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string61 = /_dcsync\.txt/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string62 = /_lsass\.txt/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string63 = /_lsassdecrypt\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string64 = /apypykatz\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string65 = /asreproast_.{0,1000}\.txt/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string66 = /dcsync\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string67 = /dpapi\/decryptor\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string68 = /get_masterkeys_from_lsass/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string69 = /gppassword\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string70 = /import\sapypykatz/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string71 = /import\spypykatz/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string72 = /info\@skelsecprojects\.com/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string73 = /install\spypykatz/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string74 = /KatzSystemArchitecture/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string75 = /kerberos\/decryptor\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string76 = /KIWI_CLOUDAP_LOGON_LIST_ENTRY_21H2/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string77 = /lsa_decryptor\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string78 = /lsa_decryptor_nt.{0,1000}\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string79 = /LSASecretDefaultPassword/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string80 = /minidump.{0,1000}minikerberos/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string81 = /pypykatz\s/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string82 = /pypykatz\.commons/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string83 = /pypykatz\.dpapi/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string84 = /pypykatz\.exe/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string85 = /pypykatz\.git/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string86 = /pypykatz\.kerberos/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string87 = /pypykatz\.lsadecryptor/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string88 = /pypykatz\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string89 = /pypykatz\.registry/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string90 = /pypykatz_rekall\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string91 = /pypykatz\-master\.zip/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string92 = /rekallreader\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string93 = /shareenum\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string94 = /spnroast_.{0,1000}\.txt/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string95 = /tasklist\s\/fi\s.{0,1000}Imagename\seq\slsass\.exe.{0,1000}\s\|\sfind\s.{0,1000}lsass/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string96 = /tspkg\/decryptor\.py/ nocase ascii wide
        // Description: Mimikatz implementation in pure Python
        // Reference: https://github.com/skelsec/pypykatz
        $string97 = /wdigest\/decryptor\.py/ nocase ascii wide

    condition:
        any of them
}
