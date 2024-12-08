rule crackmapexec
{
    meta:
        description = "Detection patterns for the tool 'crackmapexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crackmapexec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: windows default compiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string1 = " cmedb" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string2 = " empire_exec" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string3 = " empireadmin" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string4 = " enum_avproducts" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string5 = " enum_chrome" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string6 = " enum_dns" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string7 = " --force-ps32" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string8 = " --gen-relay-list " nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string9 = " get_keystrokes" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string10 = " get_netdomaincontroller" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string11 = " get_netrdpsession" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string12 = " get_timedscreenshot" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string13 = " gpp_autologin" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string14 = " gpp_password" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string15 = " invoke_sessiongopher" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string16 = " invoke_vnc" nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string17 = /\skerberos\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string18 = " --local-auth --shares" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string19 = " --loggedon-users" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string20 = " -M multirdp" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string21 = " -M pe_inject" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string22 = " -M scuffy" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string23 = " -M shellcode_inject" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string24 = " -M slinky" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string25 = " -M tokens" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string26 = " -M uac" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string27 = " -M web_delivery" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string28 = " met_inject" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string29 = " mimikittenz" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string30 = " netripper" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string31 = " --no-bruteforce " nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string32 = " --ntds-history" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string33 = " --ntds-pwdLastSet" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string34 = /\s\-p\s.{0,1000}\s\-\-amsi\-bypass\s/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string35 = " Pwn3d!" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string36 = " --rid-brute" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string37 = " smb -M mimikatz --options" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string38 = /\ssmb.{0,1000}\s\-u\s\'\'\s\-p\s\'\'/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string39 = /\ssmbexec\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string40 = /\s\-u\s.{0,1000}\s\-\-local\-auth/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string41 = /\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-lusers/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string42 = /\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-sam/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string43 = /\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-shares/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string44 = /\s\-u\s.{0,1000}\s\-p\s.{0,1000}\-\-pass\-pol/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string45 = " --wdigest disable" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string46 = " --wdigest enable" nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string47 = /\swinrm\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string48 = /\s\-\-wmi\s.{0,1000}SELECT\s/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string49 = /\swmiexec\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string50 = /\s\-\-wmi\-namespace\s\'root\\cimv2\'/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string51 = /\s\-X\s\'\$PSVersionTable\'\s/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string52 = /\s\-X\s\'\[System\.Environment\]\:\:Is64BitProcess\'/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string53 = /\$DummyServiceName/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string54 = /\$KeePassBinaryPath/ nocase ascii wide
        // Description: Variable name from script RestartKeePass.ps1 from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks  
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string55 = /\$KeePassUser/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string56 = /\.exe.{0,1000}\s\-d\slocalhost\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\/24/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string57 = /\.exe.{0,1000}\s\-u\sadministrator\s\-H\s\:.{0,1000}\-\-shares/ nocase ascii wide
        // Description: crack mapexec script used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string58 = /\/batch_cme_smb\.sh/ nocase ascii wide
        // Description: bloodhound integration with crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string59 = /\/bloodhound\.py/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string60 = "/cme smb " nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string61 = "/cme winrm " nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral move
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string62 = "/cmedb" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string63 = /\/enum_av\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string64 = /\/kerberos\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string65 = /\/mssqlexec\.py/ nocase ascii wide
        // Description: parser nessus.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string66 = /\/nessus\.py/ nocase ascii wide
        // Description: parser nmap.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string67 = /\/nmap\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string68 = "/obfuscated_scripts/" nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string69 = /\/protocols\/ftp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string70 = /\/protocols\/ldap\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string71 = /\/protocols\/mssql\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string72 = /\/protocols\/rdp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string73 = /\/protocols\/rdp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string74 = /\/protocols\/smb\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string75 = /\/protocols\/ssh\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string76 = /\/samruser\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string77 = /\/smbexec\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string78 = /\/smbldap\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string79 = /\/winrm\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string80 = /\/wmiexec\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string81 = /\/wmiexec\.py/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string82 = /\\bin\\cme\.exe/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string83 = /\\cme\.exe.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-H\s/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string84 = /\\cme\.exe.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string85 = /\\cme\.exe.{0,1000}\s\-\-shares/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string86 = /\\crackmapexecwin/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string87 = /\\Temp\\cme_hosted/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string88 = /\\Temp\\whoami\.txt/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string89 = /\\Windows\\Temp\\temp\.ps1/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string90 = "_enum_vault_creds" nocase ascii wide
        // Description: crack mapexec script used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string91 = "2eb2cc1eb661148109488b8f36aa6b248e88c0f1" nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string92 = /AddKeePassTrigger\.ps1/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string93 = /BloodHound\-modified\.ps1/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string94 = /cmd\ssmb\s.{0,1000}\-u.{0,1000}\-p/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string95 = /cme\s\-d\s.{0,1000}\s\-/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string96 = /cme\s\-d\s.{0,1000}localhost/ nocase ascii wide
        // Description: macOS default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string97 = /cme.{0,1000}\-macOS\-latest\-/ nocase ascii wide
        // Description: ubuntu default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string98 = /cme.{0,1000}\-ubuntu\-latest\-/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral move
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string99 = /cme.{0,1000}\-windows\-latest\-/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string100 = /cme\/cme\.conf/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string101 = /cme\-macOS\-latest\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string102 = /cme\-ubuntu\-latest\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string103 = /cme\-windows\-latest\-.{0,1000}\.zip/ nocase ascii wide
        // Description: crackmapexec execution name. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string104 = "crackmapexec" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string105 = "CrackMapExec" nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string106 = /crackmapexec\.exe/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string107 = /crackmapexec\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string108 = /DNS\-Enum\-.{0,1000}\-.{0,1000}\.log/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string109 = /empire_exec\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string110 = /enum_avproducts\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string111 = "--exec-method smbexec" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string112 = /get_keystrokes\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string113 = "Get-ComputerDetails" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string114 = /gpp_autologin\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string115 = /gpp_password\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string116 = "-H lm-hash:nt-hash" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string117 = "-H 'LMHASH:NTHASH'" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string118 = "-H 'NTHASH'" nocase ascii wide
        // Description: function name from nessus.py from crackmapexec.  CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string119 = "handle_nessus_file" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string120 = /handlekatz\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string121 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: hook script for lsassy from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string122 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string123 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string124 = /invoke_sessiongopher\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string125 = /keepass_discover\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string126 = "lsassy_dump" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string127 = /lsassy_dump\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string128 = /met_inject\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string129 = /mimipenguin\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string130 = /modules.{0,1000}daclread\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string131 = /ntlmv1\.py/ nocase ascii wide
        // Description: function name from nessus.py from crackmapexec.  CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string132 = "parse_nessus_file" nocase ascii wide
        // Description: function name from nmap.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string133 = "parse_nmap_xml" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string134 = /petitpotam\.py/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string135 = /RemoveKeePassTrigger\.ps1/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string136 = /RestartKeePass\.ps1/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string137 = /smbspider\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string138 = /temp.{0,1000}whoami\.txt/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string139 = /whoami\.py/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string140 = "cme smb " nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string141 = "cme smb -" nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string142 = "cme winrm " nocase ascii wide

    condition:
        any of them
}
