rule bruteratel
{
    meta:
        description = "Detection patterns for the tool 'bruteratel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bruteratel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string1 = /\sgetprivs\.c\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string2 = /\sgetprivs\.o\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string3 = /\s\-ratel\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string4 = /\.BruteRatel/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string5 = /\/BRC4_rar/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string6 = /\/bruteratel/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string7 = /\/Process\-Instrumentation\-Syscall\-Hook/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string8 = /\/vainject\.c/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string9 = /\\brc\.zip/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string10 = /\\pipe\\brutepipe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string11 = /1a279f5df4103743b823ec2a6a08436fdf63fe30/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string12 = /3fd21b20d00000021c43d21b21b43de0a012c76cf078b8d06f4620c2286f5e/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string13 = /addpriv\sSeloadDrivePrivilege/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string14 = /addresshunter\.h/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string15 = /badger_exports\.h/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string16 = /badger_svc\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string17 = /badger_template\.ps1/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string18 = /badger_x64\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string19 = /badger_x64_.{0,1000}\.bin/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string20 = /badger_x64_aws\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string21 = /BadgerAtoi/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string22 = /BadgerDispatch/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string23 = /BadgerDispatchW/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string24 = /BadgerMemcpy/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string25 = /BadgerMemset/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string26 = /BadgerStrcmp/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string27 = /BadgerStrlen/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string28 = /BadgerWcscmp/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string29 = /BadgerWcslen/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string30 = /bc3023b36063a7681db24681472b54fa11f0d4ec/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string31 = /bhttp_x64\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string32 = /Brc4ConfigExtractor\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string33 = /Brc4DecodeString/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string34 = /bruteloader/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string35 = /brute\-ratel\-/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string36 = /BruteRatel.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string37 = /BruteRatel.{0,1000}\.zip/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string38 = /bruteratel\.com\// nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string39 = /bruteratel\// nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string40 = /Brute\-Ratel\-C4/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string41 = /coffexec\s.{0,1000}\.o\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string42 = /contact_harvester/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string43 = /crisis_monitor\sstart/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string44 = /crisis_monitor\sstop/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string45 = /cryptvortex\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string46 = /dcsync_inject/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string47 = /detect\sntdll\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string48 = /etwti\-hook\./ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string49 = /getprivs\.bin/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string50 = /getprivs\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string51 = /imp_Badger/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string52 = /krb5decoder/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string53 = /ldapsentinel\s.{0,1000}\sraw\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string54 = /ldapsentinel\sforest\suser/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string55 = /list_tcppivot/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string56 = /loaddll64\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string57 = /LocateBrc4Config/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string58 = /o_getprivs/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string59 = /objexec\s.{0,1000}\.o/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string60 = /phantom_thread\s.{0,1000}\sshc\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string61 = /PIC\-Get\-Privileges/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string62 = /pivot_smb\s\\/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string63 = /pivot_winrm\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string64 = /Proxy\-DLL\-Loads/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string65 = /proxyDllLoads\.c/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string66 = /proxyDllLoads\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string67 = /psreflect\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string68 = /runshellcode\.asm/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string69 = /runshellcode\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string70 = /runshellcode\.o/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string71 = /ScanProcessForBadgerConfig/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string72 = /scdivert\slocalhost\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string73 = /schtquery\s.{0,1000}\sfull/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string74 = /set_child\swerfault\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string75 = /set_objectpipe\s\\\\/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string76 = /set_wmiconfig\s\\/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string77 = /shadowclock/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string78 = /shadowclone\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string79 = /sharpinline\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string80 = /Sharpreflect\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string81 = /shinject_ex\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string82 = /StrongLoader_x64\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string83 = /suspended_run\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string84 = /threads\sall\salertable/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string85 = /wmiexec\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string86 = /wmispawn\sselect/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string87 = /impersonate\s.{0,1000}\\/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string88 = /kerberoast\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string89 = /list_exports\s.{0,1000}\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string90 = /make_token\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string91 = /memdump\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string92 = /memex\s\/.{0,1000}\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string93 = /memhunt\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string94 = /psgrep\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string95 = /samdump\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string96 = /set_child\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string97 = /sharescan\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}
