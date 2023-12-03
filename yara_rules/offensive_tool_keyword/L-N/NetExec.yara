rule NetExec
{
    meta:
        description = "Detection patterns for the tool 'NetExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string1 = /.{0,1000}\s\-\-asreproast\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string2 = /.{0,1000}\s\-\-bloodhound\s\-\-ns\sip\s\-\-collection\sAll.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string3 = /.{0,1000}\se2e_test\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string4 = /.{0,1000}\s\-\-gen\-relay\-list\s\/tmp\/relaylistOutputFilename\.txt.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string5 = /.{0,1000}\s\-\-gmsa\-decrypt\-lsa\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string6 = /.{0,1000}\s\-\-kerberoasting\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string7 = /.{0,1000}\sldap\s.{0,1000}\s\-\-trusted\-for\-delegation.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string8 = /.{0,1000}\sldap\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-admin\-count.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string9 = /.{0,1000}\sldap\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\swhoami\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string10 = /.{0,1000}\s\-M\sempire_exec\s\-o\sLISTENER\=http\-listener.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string11 = /.{0,1000}\s\-M\sgpp_autologin.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string12 = /.{0,1000}\s\-M\skeepass_discover.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string13 = /.{0,1000}\s\-M\skeepass_trigger\s\-o\sACTION\=ALL\sUSER\=.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string14 = /.{0,1000}\s\-M\sldap\-checker\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string15 = /.{0,1000}\s\-M\spetitpotam.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string16 = /.{0,1000}\s\-M\sscuffy\s\-o\sSERVER\=127\.0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string17 = /.{0,1000}\s\-M\sshadowcoerce.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string18 = /.{0,1000}\s\-M\sslinky\s\-o\sSERVER\=.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string19 = /.{0,1000}\s\-M\sspider_plus\s\-o\sMAX_FILE_SIZE\=100.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string20 = /.{0,1000}\s\-M\swdigest\s\-o\sACTION\=disable.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string21 = /.{0,1000}\s\-M\swdigest\s\-o\sACTION\=enable.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string22 = /.{0,1000}\smssql\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\smet_inject.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string23 = /.{0,1000}\smssql\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\smssql_priv.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string24 = /.{0,1000}\smssql\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\sweb_delivery\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string25 = /.{0,1000}\s\-\-no\-bruteforce\s\-\-continue\-on\-success.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string26 = /.{0,1000}\s\-p\stest_passwords\.txt.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string27 = /.{0,1000}\srdp\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-nla\-screenshot.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string28 = /.{0,1000}\srun\snetexec\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string29 = /.{0,1000}\srun\snxc\ssmb\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string30 = /.{0,1000}\ssmb\s.{0,1000}\s\-M\slsassy.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string31 = /.{0,1000}\ssmb\s.{0,1000}\s\-M\smasky\s\-o\sCA\=.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string32 = /.{0,1000}\ssmb\s.{0,1000}\s\-M\srdp\s\-o\sACTION\=enable.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string33 = /.{0,1000}\ssmb\s.{0,1000}\s\-M\srunasppl.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string34 = /.{0,1000}\ssmb\s.{0,1000}\s\-M\szerologon.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string35 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s.{0,1000}\s\-M\sdfscoerce.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string36 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s.{0,1000}\s\-\-rid\-brute.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string37 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s.{0,1000}\s\-\-shares\s\-\-filter\-shares\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string38 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s.{0,1000}\s\-X\swhoami\s\-\-obfs.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string39 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\senum_av.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string40 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\senum_dns.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string41 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\sgpp_password.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string42 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\smet_inject\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string43 = /.{0,1000}\ssmb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-wmi\s\"select\sName\sfrom\swin32_computersystem\".{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string44 = /.{0,1000}\sSRVHOST\=127\.0\.0\.1\sSRVPORT\=4444\sRAND\=12345.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string45 = /.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\shandlekatz.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string46 = /.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\snanodump.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string47 = /.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\sntdsutil.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string48 = /.{0,1000}\swinrm\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-laps.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string49 = /.{0,1000}\swinrm\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-X\swhoami.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string50 = /.{0,1000}\s\-x\s.{0,1000}\s\-\-exec\-method\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string51 = /.{0,1000}\s\-X\swhoami\s\-\-obfs.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string52 = /.{0,1000}\/\.nxc\/obfuscated_scripts\/.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string53 = /.{0,1000}\/adcs\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string54 = /.{0,1000}\/add_computer\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string55 = /.{0,1000}\/bh_owned\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string56 = /.{0,1000}\/bin\/nxcdb.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string57 = /.{0,1000}\/daclread\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string58 = /.{0,1000}\/data\/nxc\.conf.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string59 = /.{0,1000}\/dfscoerce\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string60 = /.{0,1000}\/drop\-sc\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string61 = /.{0,1000}\/e2e_commands\.txt.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string62 = /.{0,1000}\/e2e_test\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string63 = /.{0,1000}\/empire_exec\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string64 = /.{0,1000}\/enum_av\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string65 = /.{0,1000}\/enum_dns\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string66 = /.{0,1000}\/find\-computer\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string67 = /.{0,1000}\/get\-desc\-users\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string68 = /.{0,1000}\/gpp_autologin\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string69 = /.{0,1000}\/gpp_password\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string70 = /.{0,1000}\/handlekatz\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string71 = /.{0,1000}\/hash_spider\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string72 = /.{0,1000}\/impersonate\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string73 = /.{0,1000}\/install_elevated\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string74 = /.{0,1000}\/IOXIDResolver\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string75 = /.{0,1000}\/keepass_discover\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string76 = /.{0,1000}\/keepass_trigger\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string77 = /.{0,1000}\/laps\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string78 = /.{0,1000}\/ldap\-checker\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string79 = /.{0,1000}\/lsassy_dump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string80 = /.{0,1000}\/masky\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string81 = /.{0,1000}\/met_inject\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string82 = /.{0,1000}\/ms17\-010\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string83 = /.{0,1000}\/msol\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string84 = /.{0,1000}\/mssql_priv\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string85 = /.{0,1000}\/nanodump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string86 = /.{0,1000}\/NetExec\.git.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string87 = /.{0,1000}\/netexec\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string88 = /.{0,1000}\/NetExec\-main.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string89 = /.{0,1000}\/nopac\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string90 = /.{0,1000}\/ntdsutil\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string91 = /.{0,1000}\/ntlmv1\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string92 = /.{0,1000}\/nxc\s\-\-help.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string93 = /.{0,1000}\/nxc\.exe.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string94 = /.{0,1000}\/nxc\/parsers\/ip\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string95 = /.{0,1000}\/nxc\/parsers\/nmap\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string96 = /.{0,1000}\/nxc\-ubuntu\-latest.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string97 = /.{0,1000}\/parsers\/nessus\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string98 = /.{0,1000}\/petitpotam\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string99 = /.{0,1000}\/printnightmare\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string100 = /.{0,1000}\/procdump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string101 = /.{0,1000}\/rdcman\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string102 = /.{0,1000}\/rdp\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string103 = /.{0,1000}\/reg\-query\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string104 = /.{0,1000}\/runasppl\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string105 = /.{0,1000}\/scan\-network\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string106 = /.{0,1000}\/scuffy\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string107 = /.{0,1000}\/shadowcoerce\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string108 = /.{0,1000}\/slinky\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string109 = /.{0,1000}\/spider_plus\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string110 = /.{0,1000}\/spooler\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string111 = /.{0,1000}\/teams_localdb\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string112 = /.{0,1000}\/uac\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string113 = /.{0,1000}\/usr\/src\/netexec.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string114 = /.{0,1000}\/veeam_dump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string115 = /.{0,1000}\/wdigest\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string116 = /.{0,1000}\/web_delivery\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string117 = /.{0,1000}\/webdav\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string118 = /.{0,1000}\/whoami\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string119 = /.{0,1000}\/winscp_dump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string120 = /.{0,1000}\/wireless\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string121 = /.{0,1000}\/zerologon\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string122 = /.{0,1000}\[\!\]\sDumping\sthe\sntds\scan\scrash\sthe\sDC\son\sWindows\sServer\s2019\.\sUse\sthe\soption.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string123 = /.{0,1000}\\adcs\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string124 = /.{0,1000}\\add_computer\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string125 = /.{0,1000}\\bh_owned\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string126 = /.{0,1000}\\daclread\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string127 = /.{0,1000}\\dfscoerce\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string128 = /.{0,1000}\\drop\-sc\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string129 = /.{0,1000}\\empire_exec\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string130 = /.{0,1000}\\enum_av\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string131 = /.{0,1000}\\enum_dns\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string132 = /.{0,1000}\\find\-computer\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string133 = /.{0,1000}\\get_netconnections\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string134 = /.{0,1000}\\get\-desc\-users\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string135 = /.{0,1000}\\gpp_autologin\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string136 = /.{0,1000}\\gpp_password\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string137 = /.{0,1000}\\group_members\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string138 = /.{0,1000}\\groupmembership\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string139 = /.{0,1000}\\handlekatz\.exe.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string140 = /.{0,1000}\\handlekatz\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string141 = /.{0,1000}\\hash_spider\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string142 = /.{0,1000}\\impersonate\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string143 = /.{0,1000}\\install_elevated\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string144 = /.{0,1000}\\IOXIDResolver\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string145 = /.{0,1000}\\keepass_discover\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string146 = /.{0,1000}\\keepass_trigger\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string147 = /.{0,1000}\\laps\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string148 = /.{0,1000}\\ldap\-checker\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string149 = /.{0,1000}\\lsassy_dump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string150 = /.{0,1000}\\MachineAccountQuota\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string151 = /.{0,1000}\\masky\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string152 = /.{0,1000}\\met_inject\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string153 = /.{0,1000}\\ms17\-010\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string154 = /.{0,1000}\\msol\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string155 = /.{0,1000}\\mssql_priv\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string156 = /.{0,1000}\\nanodump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string157 = /.{0,1000}\\netexec\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string158 = /.{0,1000}\\netexec\.yml.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string159 = /.{0,1000}\\NetExec\-main.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string160 = /.{0,1000}\\NetExec\-main\\.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string161 = /.{0,1000}\\nopac\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string162 = /.{0,1000}\\ntdsutil\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string163 = /.{0,1000}\\ntlmv1\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string164 = /.{0,1000}\\nxc\.exe.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string165 = /.{0,1000}\\nxc\\parsers\\ip\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string166 = /.{0,1000}\\nxc\\parsers\\nmap\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string167 = /.{0,1000}\\parsers\\nessus\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string168 = /.{0,1000}\\petitpotam\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string169 = /.{0,1000}\\printnightmare\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string170 = /.{0,1000}\\procdump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string171 = /.{0,1000}\\rdcman\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string172 = /.{0,1000}\\rdp\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string173 = /.{0,1000}\\reg\-query\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string174 = /.{0,1000}\\runasppl\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string175 = /.{0,1000}\\scan\-network\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string176 = /.{0,1000}\\scuffy\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string177 = /.{0,1000}\\shadowcoerce\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string178 = /.{0,1000}\\slinky\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string179 = /.{0,1000}\\spider_plus\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string180 = /.{0,1000}\\spooler\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string181 = /.{0,1000}\\teams_localdb\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string182 = /.{0,1000}\\Temp\\whoami\.txt.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string183 = /.{0,1000}\\uac\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string184 = /.{0,1000}\\veeam_dump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string185 = /.{0,1000}\\wdigest\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string186 = /.{0,1000}\\web_delivery\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string187 = /.{0,1000}\\webdav\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string188 = /.{0,1000}\\whoami\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string189 = /.{0,1000}\\winscp_dump\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string190 = /.{0,1000}\\wireless\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string191 = /.{0,1000}\\zerologon\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string192 = /.{0,1000}AddKeePassTrigger\.ps1.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string193 = /.{0,1000}crackmapexec\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string194 = /.{0,1000}crackmapexec\.spec.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string195 = /.{0,1000}EC235B9DDBCA83FD5BE2B80E2D543B07BE7E1052.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string196 = /.{0,1000}Exec_Command_Silent\.vbs.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string197 = /.{0,1000}Exec_Command_WithOutput\.vbs.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string198 = /.{0,1000}export\sKRB5CCNAME\=\/.{0,1000}\/impacket\/administrator\.ccache.{0,1000}\s/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string199 = /.{0,1000}HANDLEKATZ_EXE_NAME\=.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string200 = /.{0,1000}hook\-lsassy\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string201 = /.{0,1000}hook\-pypykatz\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string202 = /.{0,1000}Invoke\-Obfuscation\s\-ScriptPath\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string203 = /.{0,1000}Invoke\-Obfuscation\.psd1.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string204 = /.{0,1000}Invoke\-PSInject\.ps1.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string205 = /.{0,1000}\-M\shandlekatz\s\-o\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string206 = /.{0,1000}msol_dump\.ps1.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string207 = /.{0,1000}NetExec\sldap\s.{0,1000}\s\-\-.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string208 = /.{0,1000}NetExec\sldap\s.{0,1000}\s\-\-dc\-ip.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string209 = /.{0,1000}NetExec\sldap\s.{0,1000}\s\-M\senum_trusts.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string210 = /.{0,1000}netexec\ssmb\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string211 = /.{0,1000}NetExec\swinrm\s.{0,1000}\-\-.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string212 = /.{0,1000}NetExec\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string213 = /.{0,1000}NetExec\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string214 = /.{0,1000}nxc\sftp\s.{0,1000}bruteforce.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string215 = /.{0,1000}nxc\shttp\s.{0,1000}\-\-port.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string216 = /.{0,1000}nxc\sldap\s.{0,1000}\s\-\-admin\-count.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string217 = /.{0,1000}nxc\sldap\s.{0,1000}\s\-\-trusted\-for\-delegation.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string218 = /.{0,1000}nxc\smssql\s.{0,1000}\-\-get\-file.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string219 = /.{0,1000}nxc\smssql\s.{0,1000}\-\-local\-auth.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string220 = /.{0,1000}nxc\sssh\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string221 = /.{0,1000}nxc\swinrm\s.{0,1000}\s\-X\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string222 = /.{0,1000}nxc.{0,1000}nxcdb\.py.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string223 = /.{0,1000}nxc\.netexec:main.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string224 = /.{0,1000}nxc\.protocols\.smb.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string225 = /.{0,1000}nxcdb\-zipapp\-.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string226 = /.{0,1000}Pennyw0rth\/NetExec.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string227 = /.{0,1000}poetry\srun\sNetExec\s.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string228 = /.{0,1000}pwn3d_label\s\=\sPwn3d\!.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string229 = /.{0,1000}pyinstaller\snetexec\.spec.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string230 = /.{0,1000}python3.{0,1000}\.exe\s\.\\nxc.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string231 = /.{0,1000}RemoveKeePassTrigger\.ps1.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string232 = /.{0,1000}RestartKeePass\.ps1.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string233 = /.{0,1000}smb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s.{0,1000}\s\-M\sbh_owned.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string234 = /.{0,1000}smb\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-M\sioxidresolver.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string235 = /.{0,1000}smb\s1.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-x\s\"whoami\".{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string236 = /.{0,1000}taskkill\s\/F\s\/T\s\/IM\skeepass\.exe\s\/FI.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string237 = /.{0,1000}veeam_dump_mssql\.ps1.{0,1000}/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string238 = /.{0,1000}veeam_dump_postgresql\.ps1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
