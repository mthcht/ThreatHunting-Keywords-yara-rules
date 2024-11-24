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
        $string34 = /\s\-p\s.{0,100}\s\-\-amsi\-bypass\s/ nocase ascii wide
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
        $string38 = /\ssmb.{0,100}\s\-u\s\'\'\s\-p\s\'\'/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string39 = /\ssmbexec\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string40 = /\s\-u\s.{0,100}\s\-\-local\-auth/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string41 = /\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-lusers/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string42 = /\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-sam/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string43 = /\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-shares/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string44 = /\s\-u\s.{0,100}\s\-p\s.{0,100}\-\-pass\-pol/ nocase ascii wide
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
        $string48 = /\s\-\-wmi\s.{0,100}SELECT\s/ nocase ascii wide
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
        $string56 = /\.exe.{0,100}\s\-d\slocalhost\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\/24/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string57 = /\.exe.{0,100}\s\-u\sadministrator\s\-H\s\:.{0,100}\-\-shares/ nocase ascii wide
        // Description: bloodhound integration with crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string58 = /\/bloodhound\.py/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string59 = "/cme smb " nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string60 = "/cme winrm " nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral move
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string61 = "/cmedb" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string62 = /\/enum_av\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string63 = /\/kerberos\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string64 = /\/mssqlexec\.py/ nocase ascii wide
        // Description: parser nessus.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string65 = /\/nessus\.py/ nocase ascii wide
        // Description: parser nmap.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string66 = /\/nmap\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string67 = "/obfuscated_scripts/" nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string68 = /\/protocols\/ftp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string69 = /\/protocols\/ldap\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string70 = /\/protocols\/mssql\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string71 = /\/protocols\/rdp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string72 = /\/protocols\/rdp\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string73 = /\/protocols\/smb\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string74 = /\/protocols\/ssh\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string75 = /\/samruser\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string76 = /\/smbexec\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string77 = /\/smbldap\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string78 = /\/winrm\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string79 = /\/wmiexec\.py/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string80 = /\/wmiexec\.py/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string81 = /\\bin\\cme\.exe/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string82 = /\\cme\.exe.{0,100}\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-H\s/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string83 = /\\cme\.exe.{0,100}\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string84 = /\\cme\.exe.{0,100}\s\-\-shares/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string85 = /\\crackmapexecwin/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string86 = /\\Temp\\cme_hosted/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string87 = /\\Temp\\whoami\.txt/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string88 = /\\Windows\\Temp\\temp\.ps1/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string89 = "_enum_vault_creds" nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string90 = /AddKeePassTrigger\.ps1/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string91 = /BloodHound\-modified\.ps1/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string92 = /cmd\ssmb\s.{0,100}\-u.{0,100}\-p/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string93 = /cme\s\-d\s.{0,100}\s\-/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string94 = /cme\s\-d\s.{0,100}localhost/ nocase ascii wide
        // Description: macOS default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string95 = /cme.{0,100}\-macOS\-latest\-/ nocase ascii wide
        // Description: ubuntu default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string96 = /cme.{0,100}\-ubuntu\-latest\-/ nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral move
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string97 = /cme.{0,100}\-windows\-latest\-/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string98 = /cme\/cme\.conf/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string99 = /cme\-macOS\-latest\-.{0,100}\.zip/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string100 = /cme\-ubuntu\-latest\-.{0,100}\.zip/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string101 = /cme\-windows\-latest\-.{0,100}\.zip/ nocase ascii wide
        // Description: crackmapexec execution name. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks 
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string102 = "crackmapexec" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string103 = "CrackMapExec" nocase ascii wide
        // Description: windows default copiled executable name for crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string104 = /crackmapexec\.exe/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string105 = /crackmapexec\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string106 = /DNS\-Enum\-.{0,100}\-.{0,100}\.log/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string107 = /empire_exec\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string108 = /enum_avproducts\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string109 = "--exec-method smbexec" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string110 = /get_keystrokes\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string111 = "Get-ComputerDetails" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string112 = /gpp_autologin\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string113 = /gpp_password\.py/ nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string114 = "-H lm-hash:nt-hash" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string115 = "-H 'LMHASH:NTHASH'" nocase ascii wide
        // Description: crackmapexec command lines patterns. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string116 = "-H 'NTHASH'" nocase ascii wide
        // Description: function name from nessus.py from crackmapexec.  CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string117 = "handle_nessus_file" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string118 = /handlekatz\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string119 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: hook script for lsassy from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string120 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string121 = /hook\-lsassy\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string122 = /invoke_sessiongopher\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string123 = /keepass_discover\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string124 = "lsassy_dump" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string125 = /lsassy_dump\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string126 = /met_inject\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string127 = /mimipenguin\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string128 = /modules.{0,100}daclread\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string129 = /ntlmv1\.py/ nocase ascii wide
        // Description: function name from nessus.py from crackmapexec.  CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string130 = "parse_nessus_file" nocase ascii wide
        // Description: function name from nmap.py from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string131 = "parse_nmap_xml" nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string132 = /petitpotam\.py/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string133 = /RemoveKeePassTrigger\.ps1/ nocase ascii wide
        // Description: Keepass exploitations from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string134 = /RestartKeePass\.ps1/ nocase ascii wide
        // Description: protocol scripts from crackmapexec. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string135 = /smbspider\.py/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string136 = /temp.{0,100}whoami\.txt/ nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string137 = /whoami\.py/ nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string138 = "cme smb " nocase ascii wide
        // Description: A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string139 = "cme smb -" nocase ascii wide
        // Description: crackmapexec command lines. CrackMapExec or CME is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct Lateral Movement through targeted networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string140 = "cme winrm " nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
