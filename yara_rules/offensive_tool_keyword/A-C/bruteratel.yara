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
        $string1 = /.{0,1000}\sgetprivs\.c\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string2 = /.{0,1000}\sgetprivs\.o\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string3 = /.{0,1000}\s\-ratel\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string4 = /.{0,1000}\.BruteRatel.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string5 = /.{0,1000}\/BRC4_rar/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string6 = /.{0,1000}\/bruteratel.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string7 = /.{0,1000}\/Process\-Instrumentation\-Syscall\-Hook.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string8 = /.{0,1000}\/vainject\.c.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string9 = /.{0,1000}\\brc\.zip.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string10 = /.{0,1000}\\pipe\\brutepipe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string11 = /.{0,1000}1a279f5df4103743b823ec2a6a08436fdf63fe30.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string12 = /.{0,1000}3fd21b20d00000021c43d21b21b43de0a012c76cf078b8d06f4620c2286f5e.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string13 = /.{0,1000}addpriv\sSeloadDrivePrivilege.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string14 = /.{0,1000}addresshunter\.h.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string15 = /.{0,1000}badger_exports\.h.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string16 = /.{0,1000}badger_svc\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string17 = /.{0,1000}badger_template\.ps1.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string18 = /.{0,1000}badger_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string19 = /.{0,1000}badger_x64_.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string20 = /.{0,1000}badger_x64_aws\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string21 = /.{0,1000}BadgerAtoi.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string22 = /.{0,1000}BadgerDispatch.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string23 = /.{0,1000}BadgerDispatchW.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string24 = /.{0,1000}BadgerMemcpy.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string25 = /.{0,1000}BadgerMemset.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string26 = /.{0,1000}BadgerStrcmp.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string27 = /.{0,1000}BadgerStrlen.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string28 = /.{0,1000}BadgerWcscmp.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string29 = /.{0,1000}BadgerWcslen.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string30 = /.{0,1000}bc3023b36063a7681db24681472b54fa11f0d4ec.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string31 = /.{0,1000}bhttp_x64\.dll.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string32 = /.{0,1000}Brc4ConfigExtractor\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string33 = /.{0,1000}Brc4DecodeString.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string34 = /.{0,1000}bruteloader.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string35 = /.{0,1000}brute\-ratel\-.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string36 = /.{0,1000}BruteRatel.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string37 = /.{0,1000}BruteRatel.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string38 = /.{0,1000}bruteratel\.com\/.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string39 = /.{0,1000}bruteratel\/.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string40 = /.{0,1000}Brute\-Ratel\-C4.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string41 = /.{0,1000}coffexec\s.{0,1000}\.o\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string42 = /.{0,1000}contact_harvester.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string43 = /.{0,1000}crisis_monitor\sstart.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string44 = /.{0,1000}crisis_monitor\sstop.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string45 = /.{0,1000}cryptvortex\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string46 = /.{0,1000}dcsync_inject.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string47 = /.{0,1000}detect\sntdll\.dll.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string48 = /.{0,1000}etwti\-hook\..{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string49 = /.{0,1000}getprivs\.bin.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string50 = /.{0,1000}getprivs\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string51 = /.{0,1000}imp_Badger.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string52 = /.{0,1000}krb5decoder.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string53 = /.{0,1000}ldapsentinel\s.{0,1000}\sraw\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string54 = /.{0,1000}ldapsentinel\sforest\suser.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string55 = /.{0,1000}list_tcppivot.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string56 = /.{0,1000}loaddll64\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string57 = /.{0,1000}LocateBrc4Config.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string58 = /.{0,1000}o_getprivs.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string59 = /.{0,1000}objexec\s.{0,1000}\.o.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string60 = /.{0,1000}phantom_thread\s.{0,1000}\sshc\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string61 = /.{0,1000}PIC\-Get\-Privileges.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string62 = /.{0,1000}pivot_smb\s\\.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string63 = /.{0,1000}pivot_winrm\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string64 = /.{0,1000}Proxy\-DLL\-Loads.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string65 = /.{0,1000}proxyDllLoads\.c.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string66 = /.{0,1000}proxyDllLoads\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string67 = /.{0,1000}psreflect\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string68 = /.{0,1000}runshellcode\.asm.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string69 = /.{0,1000}runshellcode\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string70 = /.{0,1000}runshellcode\.o.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string71 = /.{0,1000}ScanProcessForBadgerConfig.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string72 = /.{0,1000}scdivert\slocalhost\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string73 = /.{0,1000}schtquery\s.{0,1000}\sfull.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string74 = /.{0,1000}set_child\swerfault\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string75 = /.{0,1000}set_objectpipe\s\\\\.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string76 = /.{0,1000}set_wmiconfig\s\\.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string77 = /.{0,1000}shadowclock.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string78 = /.{0,1000}shadowclone\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string79 = /.{0,1000}sharpinline\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string80 = /.{0,1000}Sharpreflect\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string81 = /.{0,1000}shinject_ex\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string82 = /.{0,1000}StrongLoader_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string83 = /.{0,1000}suspended_run\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string84 = /.{0,1000}threads\sall\salertable.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string85 = /.{0,1000}wmiexec\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string86 = /.{0,1000}wmispawn\sselect.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string87 = /grab_token\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string88 = /impersonate\s.{0,1000}\\.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string89 = /kerberoast\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string90 = /list_exports\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string91 = /make_token\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string92 = /memdump\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string93 = /memex\s\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string94 = /memhunt\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string95 = /ps_ex\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string96 = /psgrep\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string97 = /samdump\s.{0,1000}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string98 = /set_child\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string99 = /sharescan\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}
