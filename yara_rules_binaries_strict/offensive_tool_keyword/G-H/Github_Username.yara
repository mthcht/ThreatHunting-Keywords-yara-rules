rule Github_Username
{
    meta:
        description = "Detection patterns for the tool 'Github Username' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Github Username"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: github Penetration tester repo hosting malicious code
        // Reference: https://github.com/attackercan/
        $string1 = "/attackercan/" nocase ascii wide
        // Description: Github username of known powershell offensive modules and scripts
        // Reference: https://github.com/Ben0xA
        $string2 = "/Ben0xA/" nocase ascii wide
        // Description: Github username known for exploitation tools. Web application security researcher. Current Location: Moscow. Russia
        // Reference: https://github.com/Bo0oM
        $string3 = "/Bo0oM" nocase ascii wide
        // Description: Github username Red teamer @ Outflank. Passionate about networking and cybersecurity.  known for exploitation tools dev
        // Reference: https://github.com/Cn33liz
        $string4 = "/Cn33liz" nocase ascii wide
        // Description: Github username Red teamer @ Outflank.Passionate about networking and cybersecurity. known for exploitation tools dev
        // Reference: https://twitter.com/Cneelis
        $string5 = "/Cneelis" nocase ascii wide
        // Description: Zero day code injection and vulnerabilities github repo
        // Reference: https://github.com/Cybellum
        $string6 = "/Cybellum" nocase ascii wide
        // Description: pentest tools repo
        // Reference: https://github.com/CyDefUnicorn
        $string7 = "/CyDefUnicorn" nocase ascii wide
        // Description: Co-founder of Empire. BloodHound. and the Veil-Framework | PowerSploit developer | krb lover | Microsoft PowerShell MVP | Security at the misfortune of others
        // Reference: https://github.com/HarmJ0y
        $string8 = "/HarmJ0y" nocase ascii wide
        // Description: github username. 'My name is Halil Dalabasmaz. I consider myself Pwner.' containing exploitation tools
        // Reference: https://github.com/hlldz
        $string9 = "/hlldz" nocase ascii wide
        // Description: github username 'hacker' hosting exploitaitont tools and passwords attacks tools
        // Reference: https://github.com/m4ll0k
        $string10 = "/m4ll0k/" nocase ascii wide
        // Description: pentester github username hosting exploitation tools
        // Reference: https://github.com/m8r0wn
        $string11 = "/m8r0wn/" nocase ascii wide
        // Description: github repo hosting various exploitation tools
        // Reference: https://github.com/trustedsec
        $string12 = "/trustedsec/" nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/x0rz
        $string13 = "/x0rz/" nocase ascii wide
        // Description: redteam tools github repo 
        // Reference: https://github.com/cryptolok
        $string14 = /\\cryptolok/ nocase ascii wide
        // Description: Github username of pentester known for enumeration tools
        // Reference: https://github.com/aboul3la
        $string15 = "aboul3la" nocase ascii wide
        // Description: This repo contains some Antimalware Scan Interface (AMSI) bypass / avoidance methods i found on different Blog Posts.
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string16 = "Amsi-Bypass" nocase ascii wide
        // Description: Open source testing tools for the SDR & security community
        // Reference: https://github.com/BastilleResearch
        $string17 = "BastilleResearch" nocase ascii wide
        // Description: Cybersecurity Engineers and Offensive Security enthusiasts actively maintaining/updating Powershell Empire in our spare time.
        // Reference: https://github.com/BC-SECURITY
        $string18 = "BC-SECURITY" nocase ascii wide
        // Description: github username known for repos on passwords exploitation and offensive tools
        // Reference: https://github.com/berzerk0
        $string19 = "berzerk0" nocase ascii wide
        // Description: This github account maps to the Black Hat Arsenal tools since its inception in 2011. For readibility. the tools are classified by category and not by session.
        // Reference: https://github.com/toolswatch/blackhat-arsenal-tools
        $string20 = "blackhat-arsenal-tools" nocase ascii wide
        // Description: malware and offensive tools developper 
        // Reference: https://github.com/byt3bl33d3r
        $string21 = "byt3bl33d3r" nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/Coalfire-Research
        $string22 = "Coalfire-Research" nocase ascii wide
        // Description: github user hosting malicious code and exploitation tools
        // Reference: https://github.com/curi0usJack
        $string23 = "curi0usJack" nocase ascii wide
        // Description: Github user: A hacker. high&low-level coder and a lot of things between. An extremely curious creature loves to learn. Break things or make things that break things.
        // Reference: https://github.com/D4Vinci/
        $string24 = "D4Vinci" nocase ascii wide
        // Description: Github user author of powershell obfuscation tools
        // Reference: https://github.com/danielbohannon
        $string25 = "danielbohannon" nocase ascii wide
        // Description: github user name hosting exploitation tools:hacker. scripting. recon. OSINT. automation
        // Reference: https://github.com/dchrastil
        $string26 = "dchrastil" nocase ascii wide
        // Description: Github Author of malicious scripts and eploitaiton tools 
        // Reference: https://github.com/deepzec
        $string27 = "deepzec" nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/DominicBreuker
        $string28 = "DominicBreuker" nocase ascii wide
        // Description: Github Author of malicious script and eploitaiton tools 
        // Reference: https://github.com/enigma0x3
        $string29 = "enigma0x3" nocase ascii wide
        // Description: github username of hacker known for sniffing and spoofing exploitation tools
        // Reference: https://github.com/evilsocket
        $string30 = "evilsocket" nocase ascii wide
        // Description: FortyNorth Security is a computer security consultancy specializing in offensive security work. We regularly perform red team assessments. pen tests. and more
        // Reference: https://github.com/FortyNorthSecurity
        $string31 = "FortyNorthSecurity" nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/g0tmi1k
        $string32 = "g0tmi1k" nocase ascii wide
        // Description: Github username known for exploitation toos and scripts
        // Reference: https://github.com/Arno0x
        $string33 = /github\.com\/Arno0x/ nocase ascii wide
        // Description: Private professional services firm providing offensive security testing to the Fortune 500. serving exploitation tools on github
        // Reference: https://github.com/BishopFox
        $string34 = /github\.com\/BishopFox/ nocase ascii wide
        // Description: Github user hosting exploitation tools for pentest and redteam
        // Reference: https://github.com/dafthack
        $string35 = /github\.com\/dafthack/ nocase ascii wide
        // Description: github repo name containing multiple exploitation tools
        // Reference: https://github.com/GoSecure
        $string36 = /github\.com\/GoSecure/ nocase ascii wide
        // Description: github repo name hosting securty tools and exploitation tools
        // Reference: https://github.com/nccgroup
        $string37 = /github\.com\/nccgroup/ nocase ascii wide
        // Description: An infosec security researcher & penetration tester. hosting offensive tools
        // Reference: https://github.com/quickbreach
        $string38 = /github\.com\/quickbreach/ nocase ascii wide
        // Description: github repo of orange cyberdefense red team
        // Reference: https://github.com/sensepost
        $string39 = /github\.com\/sensepost/ nocase ascii wide
        // Description: Welcome to the Infection Monkey! The Infection Monkey is an open source security tool for testing a data centers resiliency to perimeter breaches and internal server infection. The Monkey uses various methods to self propagate across a data center and reports success to a centralized Monkey Island server
        // Reference: https://github.com/h0nus
        $string40 = /guardicore.{0,100}monkey/ nocase ascii wide
        // Description: An Open Source Hacking Tools database
        // Reference: https://github.com/Hack-with-Github
        $string41 = "Hack-with-Github" nocase ascii wide
        // Description: powershell forensic tools
        // Reference: https://github.com/Invoke-IR
        $string42 = "Invoke-IR" nocase ascii wide
        // Description: gthub username hosting malware samples and exploitation tools
        // Reference: https://github.com/itsKindred
        $string43 = "itsKindred" nocase ascii wide
        // Description: github username. a knack for cryptography. computer vision. opensource software and infosec. hosting infosec tools used by pentester
        // Reference: https://github.com/jedisct1
        $string44 = "jedisct1" nocase ascii wide
        // Description: github repo name containing multiple tools for log exploitation
        // Reference: https://github.com/JPCERTCC
        $string45 = "JPCERTCC" nocase ascii wide
        // Description: github repo name hosting windows kernel exploits
        // Reference: https://github.com/SecWiki/windows-kernel-exploits
        $string46 = "kernel-exploits" nocase ascii wide
        // Description: username Kuba Gretzky hosting sniffing and spoofing exploitation tools
        // Reference: https://github.com/kgretzky
        $string47 = "kgretzky" nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/khast3x
        $string48 = "khast3x" nocase ascii wide
        // Description: exploitation tools for attackers
        // Reference: https://github.com/klsecservices
        $string49 = "klsecservices" nocase ascii wide
        // Description: github username. creator of patator and exploitation tools
        // Reference: https://github.com/lanjelot
        $string50 = "lanjelot" nocase ascii wide
        // Description: github repo name hosting exploitation tools
        // Reference: https://github.com/leapsecurity
        $string51 = "leapsecurity" nocase ascii wide
        // Description: Github username of hacker known for malware pocs and  windows exploitations
        // Reference: https://github.com/LordNoteworthy
        $string52 = "LordNoteworthy" nocase ascii wide
        // Description: github username hosting offensive tools 
        // Reference: https://github.com/matterpreter
        $string53 = "matterpreter" nocase ascii wide
        // Description: MDSecs ActiveBreach Team. own a github repo with lots of exploitation tools https://www.mdsec.co.uk/services/red-teaming/
        // Reference: https://github.com/mdsecactivebreach/
        $string54 = "mdsecactivebreach" nocase ascii wide
        // Description: MOGWAI LABS is an infosec boutique with a strong emphasis on offensive security github repo hosting offensive tools
        // Reference: https://github.com/mogwailabs
        $string55 = "mogwailabs" nocase ascii wide
        // Description: github repo that was hosting exploitation tools. may be used by other exploitation tools 
        // Reference: https://github.com/MooseDojo
        $string56 = "MooseDojo" nocase ascii wide
        // Description: github username Mostly Red Team tools for penetration testing. Twitter - @MrUn1k0d3r
        // Reference: https://github.com/Mr-Un1k0d3r
        $string57 = "Mr-Un1k0d3r" nocase ascii wide
        // Description: used to be a malware repo aso hosting exploitation tools
        // Reference: https://github.com/mwrlabs
        $string58 = "mwrlabs" nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/n1nj4sec
        $string59 = "n1nj4sec" nocase ascii wide
        // Description: author of RAT tools on github
        // Reference: https://github.com/neoneggplant
        $string60 = "neoneggplant" nocase ascii wide
        // Description: Author of APT simulator
        // Reference: https://github.com/NextronSystems
        $string61 = "NextronSystems" nocase ascii wide
        // Description: github user hosting exploitation and recon tools
        // Reference: https://github.com/nyxgeek
        $string62 = "nyxgeek" nocase ascii wide
        // Description: resources for pentesters
        // Reference: https://github.com/obscuritylabs
        $string63 = "obscuritylabs" nocase ascii wide
        // Description: github repo name hosting lots of exploitation tools
        // Reference: https://github.com/P0cL4bs
        $string64 = "P0cL4bs" nocase ascii wide
        // Description: github repo name - privileges exploitation and offensive tools
        // Reference: https://github.com/pentestmonkey
        $string65 = "pentestmonkey" nocase ascii wide
        // Description: Pentest hosting multiple offensive tools
        // Reference: https://github.com/r00t-3xp10it
        $string66 = "r00t-3xp10it" nocase ascii wide
        // Description: github user author of various offensive tools
        // Reference: https://github.com/rasta-mouse
        $string67 = "rasta-mouse" nocase ascii wide
        // Description: github user Security Researcher @F5Networks hosting reverse tools and other pentester tools for data exfiltration and password attacks
        // Reference: https://github.com/realgam3
        $string68 = "realgam3" nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/RedTeamOperations
        $string69 = "RedTeamOperations" nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/s0lst1c3
        $string70 = "s0lst1c3" nocase ascii wide
        // Description: github username hosting offensive tools. mostly for web hacking
        // Reference: https://github.com/s0md3v
        $string71 = "s0md3v" nocase ascii wide
        // Description: Github username of hackr known for exploitation scripts Pentesting. scripting and pwning!
        // Reference: https://github.com/S3cur3Th1sSh1t
        $string72 = "S3cur3Th1sSh1t" nocase ascii wide
        // Description: s7scan is a tool that scans networks. enumerates Siemens PLCs and gathers basic information about them. such as PLC firmware and hardwaare version. network configuration and security parameters. It is completely written on Python.
        // Reference: https://github.com/klsecservices/s7scan
        $string73 = "s7scan" nocase ascii wide
        // Description: github username hosting exploitation tools
        // Reference: https://github.com/sailay1996
        $string74 = "sailay1996" nocase ascii wide
        // Description: github username - Pentester. Red teamer. OSCP. Former wardialer and OKI 900 enthusiast. Senior Security Consultant @ctxis hosting offensve tools
        // Reference: https://github.com/sc0tfree
        $string75 = "sc0tfree" nocase ascii wide
        // Description: github username hosting post exploitation tools
        // Reference: https://github.com/Screetsec
        $string76 = "Screetsec" nocase ascii wide
        // Description: github username hosting  exploitation tools
        // Reference: https://github.com/secgroundzero
        $string77 = "secgroundzero" nocase ascii wide
        // Description: github username hosting process injection codes 
        // Reference: https://github.com/secrary
        $string78 = "secrary" nocase ascii wide
        // Description: pentest documentations
        // Reference: https://github.com/securitywithoutborders
        $string79 = "securitywithoutborders" nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/SilverPoision
        $string80 = "SilverPoision" nocase ascii wide
        // Description: github repo Open source IT security software tools and information and exploitation tools
        // Reference: https://github.com/SySS-Research
        $string81 = "SySS-Research" nocase ascii wide
        // Description: github repo hosting post exploitation tools
        // Reference: https://github.com/threatexpress
        $string82 = "threatexpress" nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/tiagorlampert
        $string83 = "tiagorlampert" nocase ascii wide
        // Description: github repo hosting offensive tools and exploitation frameworks
        // Reference: https://github.com/True-Demon
        $string84 = "True-Demon" nocase ascii wide
        // Description: github repo hosting sniffing spoofing and data exfiltration tools
        // Reference: https://github.com/TryCatchHCF
        $string85 = "TryCatchHCF" nocase ascii wide
        // Description: github repo hosting offensive tools and exploitation frameworks
        // Reference: https://github.com/Und3rf10w
        $string86 = "Und3rf10w" nocase ascii wide
        // Description: github repo hosting obfuscation tools
        // Reference: https://github.com/unixpickle
        $string87 = "unixpickle" nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/virajkulkarni14
        $string88 = "virajkulkarni14" nocase ascii wide
        // Description: github username hosting post exploitation tools and recon tools
        // Reference: https://github.com/Viralmaniar
        $string89 = "Viralmaniar" nocase ascii wide
        // Description: github username hosting red team tools
        // Reference: https://github.com/vysecurity
        $string90 = "vysecurity" nocase ascii wide
        // Description: Github username known for password exploitation and offensive tools
        // Reference: https://github.com/x90skysn3k
        $string91 = "x90skysn3k" nocase ascii wide
        // Description: github repo username hosting red team tools
        // Reference: https://github.com/xillwillx
        $string92 = "xillwillx" nocase ascii wide
        // Description: github username hosting obfuscation and exploitation tools
        // Reference: https://github.com/xoreaxeaxeax
        $string93 = "xoreaxeaxeax" nocase ascii wide
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
