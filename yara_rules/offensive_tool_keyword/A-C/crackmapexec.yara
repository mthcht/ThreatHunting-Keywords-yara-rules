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
        $string1 = /\scmedb/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string2 = /\sempire_exec/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string3 = /\sempireadmin/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string4 = /\senum_avproducts/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string5 = /\senum_chrome/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string6 = /\senum_dns/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string7 = /\s\-\-force\-ps32/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string8 = /\s\-\-gen\-relay\-list\s/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string9 = /\sget_keystrokes/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string10 = /\sget_netdomaincontroller/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string11 = /\sget_netrdpsession/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string12 = /\sget_timedscreenshot/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string13 = /\sgpp_autologin/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string14 = /\sgpp_password/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string15 = /\sinvoke_sessiongopher/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string16 = /\sinvoke_vnc/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string17 = /\skerberos\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string18 = /\s\-\-local\-auth\s\-\-shares/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string19 = /\s\-\-loggedon\-users/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string20 = /\s\-M\smultirdp/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string21 = /\s\-M\spe_inject/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string22 = /\s\-M\sscuffy/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string23 = /\s\-M\sshellcode_inject/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string24 = /\s\-M\sslinky/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string25 = /\s\-M\stokens/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string26 = /\s\-M\suac/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string27 = /\s\-M\sweb_delivery/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string28 = /\smet_inject/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string29 = /\smimikittenz/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string30 = /\snetripper/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string31 = /\s\-\-no\-bruteforce\s/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string32 = /\s\-\-ntds\-history/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string33 = /\s\-\-ntds\-pwdLastSet/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string34 = /\s\-p\s.{0,1000}\s\-\-amsi\-bypass\s/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string35 = /\sPwn3d\!/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string36 = /\s\-\-rid\-brute/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string37 = /\ssmb\s\-M\smimikatz\s\-\-options/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string38 = /\ssmb.{0,1000}\s\-u\s\'\'\s\-p\s\'\'/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string39 = /\ssmbexec\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string40 = /\s\-u\s.{0,1000}\s\-\-local\-auth/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string41 = /\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-lusers/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string42 = /\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-sam/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string43 = /\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-shares/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string44 = /\s\-u\s.{0,1000}\s\-p\s.{0,1000}\-\-pass\-pol/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string45 = /\s\-\-wdigest\sdisable/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string46 = /\s\-\-wdigest\senable/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string47 = /\swinrm\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string48 = /\s\-\-wmi\s.{0,1000}SELECT\s/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string49 = /\swmiexec\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string50 = /\s\-\-wmi\-namespace\s\'root\\cimv2\'/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string51 = /\s\-X\s\'\$PSVersionTable\'\s/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string52 = /\s\-X\s\'\[System\.Environment\]::Is64BitProcess\'/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string53 = /\$DummyServiceName/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string54 = /\$KeePassBinaryPath/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string55 = /\$KeePassUser/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string56 = /\.exe.{0,1000}\s\-d\slocalhost\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\/24/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string57 = /\.exe.{0,1000}\s\-u\sadministrator\s\-H\s:.{0,1000}\-\-shares/ nocase ascii wide
        // Description: bloodhound integration with crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string58 = /\/bloodhound\.py/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string59 = /\/cme\ssmb\s/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string60 = /\/cme\swinrm\s/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral move
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string61 = /\/cmedb/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string62 = /\/enum_av\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string63 = /\/kerberos\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string64 = /\/mssqlexec\.py/ nocase ascii wide
        // Description: parser nessus.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string65 = /\/nessus\.py/ nocase ascii wide
        // Description: parser nmap.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string66 = /\/nmap\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string67 = /\/obfuscated_scripts\// nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string68 = /\/protocols\/ftp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string69 = /\/protocols\/ldap\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string70 = /\/protocols\/mssql\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string71 = /\/protocols\/rdp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string72 = /\/protocols\/rdp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string73 = /\/protocols\/smb\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string74 = /\/protocols\/ssh\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string75 = /\/samruser\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string76 = /\/smbexec\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string77 = /\/smbldap\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string78 = /\/winrm\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string79 = /\/wmiexec\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string80 = /\/wmiexec\.py/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string81 = /\\bin\\cme\.exe/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string82 = /\\cme\.exe.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-H\s/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string83 = /\\cme\.exe.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string84 = /\\cme\.exe.{0,1000}\s\-\-shares/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string85 = /\\crackmapexecwin/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string86 = /_enum_vault_creds/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string87 = /AddKeePassTrigger\.ps1/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string88 = /BloodHound\-modified\.ps1/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string89 = /cmd\ssmb\s.{0,1000}\-u.{0,1000}\-p/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string90 = /cme\s\-d\s.{0,1000}\s\-/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string91 = /cme\s\-d\s.{0,1000}localhost/ nocase ascii wide
        // Description: macOS default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string92 = /cme.{0,1000}\-macOS\-latest\-/ nocase ascii wide
        // Description: ubuntu default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string93 = /cme.{0,1000}\-ubuntu\-latest\-/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral move
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string94 = /cme.{0,1000}\-windows\-latest\-/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string95 = /cme\/cme\.conf/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string96 = /cme\-macOS\-latest\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string97 = /cme\-ubuntu\-latest\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string98 = /cme\-windows\-latest\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string99 = /CrackMapExec/ nocase ascii wide
        // Description: crackmapexec execution name. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string100 = /crackmapexec/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string101 = /crackmapexec\.exe/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string102 = /crackmapexec\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string103 = /DNS\-Enum\-.{0,1000}\-.{0,1000}\.log/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string104 = /empire_exec\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string105 = /enum_avproducts\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string106 = /\-\-exec\-method\ssmbexec/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string107 = /get_keystrokes\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string108 = /Get\-ComputerDetails/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string109 = /gpp_autologin\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string110 = /gpp_password\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string111 = /\-H\slm\-hash:nt\-hash/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string112 = /\-H\s\'LMHASH:NTHASH\'/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string113 = /\-H\s\'NTHASH\'/ nocase ascii wide
        // Description: function name from nessus.py from crackmapexec.  CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string114 = /handle_nessus_file/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string115 = /handlekatz\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string116 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string117 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: hook script for lsassy from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string118 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string119 = /invoke_sessiongopher\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string120 = /keepass_discover\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string121 = /lsassy_dump/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string122 = /lsassy_dump\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string123 = /met_inject\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string124 = /mimipenguin\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string125 = /modules.{0,1000}daclread\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string126 = /ntlmv1\.py/ nocase ascii wide
        // Description: function name from nessus.py from crackmapexec.  CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string127 = /parse_nessus_file/ nocase ascii wide
        // Description: function name from nmap.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string128 = /parse_nmap_xml/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string129 = /petitpotam\.py/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string130 = /RemoveKeePassTrigger\.ps1/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string131 = /RestartKeePass\.ps1/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string132 = /smbspider\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string133 = /temp.{0,1000}whoami\.txt/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string134 = /whoami\.py/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string135 = /cme\ssmb\s/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string136 = /cme\ssmb\s\-/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string137 = /cme\swinrm\s/ nocase ascii wide

    condition:
        any of them
}
