rule crackmapexec
{
    meta:
        description = "Detection patterns for the tool 'crackmapexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crackmapexec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string1 = /.{0,1000}\scmedb/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string2 = /.{0,1000}\sempire_exec.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string3 = /.{0,1000}\sempireadmin.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string4 = /.{0,1000}\senum_avproducts.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string5 = /.{0,1000}\senum_chrome.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string6 = /.{0,1000}\senum_dns.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string7 = /.{0,1000}\s\-\-force\-ps32/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string8 = /.{0,1000}\s\-\-gen\-relay\-list\s.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string9 = /.{0,1000}\sget_keystrokes.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string10 = /.{0,1000}\sget_netdomaincontroller.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string11 = /.{0,1000}\sget_netrdpsession.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string12 = /.{0,1000}\sget_timedscreenshot.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string13 = /.{0,1000}\sgpp_autologin.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string14 = /.{0,1000}\sgpp_password.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string15 = /.{0,1000}\sinvoke_sessiongopher.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string16 = /.{0,1000}\sinvoke_vnc.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string17 = /.{0,1000}\skerberos\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string18 = /.{0,1000}\s\-\-local\-auth\s\-\-shares.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string19 = /.{0,1000}\s\-\-loggedon\-users.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string20 = /.{0,1000}\s\-M\smultirdp.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string21 = /.{0,1000}\s\-M\spe_inject.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string22 = /.{0,1000}\s\-M\sscuffy.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string23 = /.{0,1000}\s\-M\sshellcode_inject.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string24 = /.{0,1000}\s\-M\sslinky/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string25 = /.{0,1000}\s\-M\stokens.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string26 = /.{0,1000}\s\-M\suac/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string27 = /.{0,1000}\s\-M\sweb_delivery.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string28 = /.{0,1000}\smet_inject.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string29 = /.{0,1000}\smimikittenz.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string30 = /.{0,1000}\snetripper.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string31 = /.{0,1000}\s\-\-no\-bruteforce\s.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string32 = /.{0,1000}\s\-\-ntds\-history.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string33 = /.{0,1000}\s\-\-ntds\-pwdLastSet.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string34 = /.{0,1000}\s\-p\s.{0,1000}\s\-\-amsi\-bypass\s.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string35 = /.{0,1000}\sPwn3d\!.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string36 = /.{0,1000}\s\-\-rid\-brute.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string37 = /.{0,1000}\ssmb\s\-M\smimikatz\s\-\-options.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string38 = /.{0,1000}\ssmb.{0,1000}\s\-u\s\'\'\s\-p\s\'\'.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string39 = /.{0,1000}\ssmbexec\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string40 = /.{0,1000}\s\-u\s.{0,1000}\s\-\-local\-auth.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string41 = /.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-lusers.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string42 = /.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-sam/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string43 = /.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-shares.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string44 = /.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\-\-pass\-pol.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string45 = /.{0,1000}\s\-\-wdigest\sdisable.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string46 = /.{0,1000}\s\-\-wdigest\senable.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string47 = /.{0,1000}\swinrm\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string48 = /.{0,1000}\s\-\-wmi\s.{0,1000}SELECT\s.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string49 = /.{0,1000}\swmiexec\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string50 = /.{0,1000}\s\-\-wmi\-namespace\s\'root\\cimv2\'.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string51 = /.{0,1000}\s\-X\s\'\$PSVersionTable\'\s.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string52 = /.{0,1000}\s\-X\s\'\[System\.Environment\]::Is64BitProcess\'.{0,1000}/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string53 = /.{0,1000}\$DummyServiceName.{0,1000}/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string54 = /.{0,1000}\$KeePassBinaryPath.{0,1000}/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string55 = /.{0,1000}\$KeePassUser.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string56 = /.{0,1000}\.exe.{0,1000}\s\-d\slocalhost\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\/24.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string57 = /.{0,1000}\.exe.{0,1000}\s\-u\sadministrator\s\-H\s:.{0,1000}\-\-shares.{0,1000}/ nocase ascii wide
        // Description: bloodhound integration with crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string58 = /.{0,1000}\/bloodhound\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string59 = /.{0,1000}\/cme\ssmb\s.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string60 = /.{0,1000}\/cme\swinrm\s.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral move
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string61 = /.{0,1000}\/cmedb/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string62 = /.{0,1000}\/enum_av\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string63 = /.{0,1000}\/kerberos\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string64 = /.{0,1000}\/mssqlexec\.py.{0,1000}/ nocase ascii wide
        // Description: parser nessus.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string65 = /.{0,1000}\/nessus\.py.{0,1000}/ nocase ascii wide
        // Description: parser nmap.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string66 = /.{0,1000}\/nmap\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string67 = /.{0,1000}\/obfuscated_scripts\/.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string68 = /.{0,1000}\/protocols\/ftp\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string69 = /.{0,1000}\/protocols\/ldap\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string70 = /.{0,1000}\/protocols\/mssql\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string71 = /.{0,1000}\/protocols\/rdp\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string72 = /.{0,1000}\/protocols\/rdp\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string73 = /.{0,1000}\/protocols\/smb\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string74 = /.{0,1000}\/protocols\/ssh\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string75 = /.{0,1000}\/samruser\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string76 = /.{0,1000}\/smbexec\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string77 = /.{0,1000}\/smbldap\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string78 = /.{0,1000}\/winrm\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string79 = /.{0,1000}\/wmiexec\.py.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string80 = /.{0,1000}\/wmiexec\.py.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string81 = /.{0,1000}\\bin\\cme\.exe.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string82 = /.{0,1000}\\cme\.exe.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-H\s.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string83 = /.{0,1000}\\cme\.exe.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string84 = /.{0,1000}\\cme\.exe.{0,1000}\s\-\-shares.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string85 = /.{0,1000}\\crackmapexecwin.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string86 = /.{0,1000}_enum_vault_creds.{0,1000}/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string87 = /.{0,1000}AddKeePassTrigger\.ps1.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string88 = /.{0,1000}BloodHound\-modified\.ps1.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string89 = /.{0,1000}cmd\ssmb\s.{0,1000}\-u.{0,1000}\-p.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string90 = /.{0,1000}cme\s\-d\s.{0,1000}\s\-.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string91 = /.{0,1000}cme\s\-d\s.{0,1000}localhost.{0,1000}/ nocase ascii wide
        // Description: macOS default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string92 = /.{0,1000}cme.{0,1000}\-macOS\-latest\-.{0,1000}/ nocase ascii wide
        // Description: ubuntu default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string93 = /.{0,1000}cme.{0,1000}\-ubuntu\-latest\-.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral move
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string94 = /.{0,1000}cme.{0,1000}\-windows\-latest\-.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string95 = /.{0,1000}cme\/cme\.conf.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string96 = /.{0,1000}cme\-macOS\-latest\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string97 = /.{0,1000}cme\-ubuntu\-latest\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string98 = /.{0,1000}cme\-windows\-latest\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string99 = /.{0,1000}CrackMapExec.{0,1000}/ nocase ascii wide
        // Description: crackmapexec execution name. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string100 = /.{0,1000}crackmapexec.{0,1000}/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string101 = /.{0,1000}crackmapexec\.exe.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string102 = /.{0,1000}crackmapexec\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string103 = /.{0,1000}DNS\-Enum\-.{0,1000}\-.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string104 = /.{0,1000}empire_exec\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string105 = /.{0,1000}enum_avproducts\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string106 = /.{0,1000}\-\-exec\-method\ssmbexec.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string107 = /.{0,1000}get_keystrokes\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string108 = /.{0,1000}Get\-ComputerDetails.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string109 = /.{0,1000}gpp_autologin\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string110 = /.{0,1000}gpp_password\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string111 = /.{0,1000}\-H\slm\-hash:nt\-hash.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string112 = /.{0,1000}\-H\s\'LMHASH:NTHASH\'.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string113 = /.{0,1000}\-H\s\'NTHASH\'.{0,1000}/ nocase ascii wide
        // Description: function name from nessus.py from crackmapexec.  CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string114 = /.{0,1000}handle_nessus_file.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string115 = /.{0,1000}handlekatz\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string116 = /.{0,1000}hook\-lsassy\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string117 = /.{0,1000}hook\-lsassy\.py.{0,1000}/ nocase ascii wide
        // Description: hook script for lsassy from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string118 = /.{0,1000}hook\-lsassy\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string119 = /.{0,1000}invoke_sessiongopher\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string120 = /.{0,1000}keepass_discover\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string121 = /.{0,1000}lsassy_dump.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string122 = /.{0,1000}lsassy_dump\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string123 = /.{0,1000}met_inject\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string124 = /.{0,1000}mimipenguin\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string125 = /.{0,1000}modules.{0,1000}daclread\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string126 = /.{0,1000}ntlmv1\.py.{0,1000}/ nocase ascii wide
        // Description: function name from nessus.py from crackmapexec.  CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string127 = /.{0,1000}parse_nessus_file.{0,1000}/ nocase ascii wide
        // Description: function name from nmap.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string128 = /.{0,1000}parse_nmap_xml.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string129 = /.{0,1000}petitpotam\.py.{0,1000}/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string130 = /.{0,1000}RemoveKeePassTrigger\.ps1.{0,1000}/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string131 = /.{0,1000}RestartKeePass\.ps1.{0,1000}/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string132 = /.{0,1000}smbspider\.py.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string133 = /.{0,1000}temp.{0,1000}whoami\.txt.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string134 = /.{0,1000}whoami\.py.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string135 = /cme\ssmb\s.{0,1000}/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string136 = /cme\ssmb\s\-.{0,1000}/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string137 = /cme\swinrm\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
