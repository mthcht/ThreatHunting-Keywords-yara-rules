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
        $string1 = /.{0,1000}\/attackercan\/.{0,1000}/ nocase ascii wide
        // Description: Github username of known powershell offensive modules and scripts
        // Reference: https://github.com/Ben0xA
        $string2 = /.{0,1000}\/Ben0xA\/.{0,1000}/ nocase ascii wide
        // Description: Github username known for exploitation tools. Web application security researcher. Current Location: Moscow. Russia
        // Reference: https://github.com/Bo0oM
        $string3 = /.{0,1000}\/Bo0oM.{0,1000}/ nocase ascii wide
        // Description: Github username known for network exploitation tools
        // Reference: https://github.com/chrisk44/Hijacker
        $string4 = /.{0,1000}\/chrisk44\/.{0,1000}/ nocase ascii wide
        // Description: Github username Red teamer @ Outflank. Passionate about networking and cybersecurity.  known for exploitation tools dev
        // Reference: https://github.com/Cn33liz
        $string5 = /.{0,1000}\/Cn33liz.{0,1000}/ nocase ascii wide
        // Description: Github username Red teamer @ Outflank.Passionate about networking and cybersecurity. known for exploitation tools dev
        // Reference: https://twitter.com/Cneelis
        $string6 = /.{0,1000}\/Cneelis.{0,1000}/ nocase ascii wide
        // Description: Zero day code injection and vulnerabilities github repo
        // Reference: https://github.com/Cybellum
        $string7 = /.{0,1000}\/Cybellum.{0,1000}/ nocase ascii wide
        // Description: pentest tools repo
        // Reference: https://github.com/CyDefUnicorn
        $string8 = /.{0,1000}\/CyDefUnicorn.{0,1000}/ nocase ascii wide
        // Description: Co-founder of Empire. BloodHound. and the Veil-Framework | PowerSploit developer | krb lover | Microsoft PowerShell MVP | Security at the misfortune of others
        // Reference: https://github.com/HarmJ0y
        $string9 = /.{0,1000}\/HarmJ0y.{0,1000}/ nocase ascii wide
        // Description: github username. 'My name is Halil Dalabasmaz. I consider myself Pwner.' containing exploitation tools
        // Reference: https://github.com/hlldz
        $string10 = /.{0,1000}\/hlldz.{0,1000}/ nocase ascii wide
        // Description: github username 'hacker' hosting exploitaitont tools and passwords attacks tools
        // Reference: https://github.com/m4ll0k
        $string11 = /.{0,1000}\/m4ll0k\/.{0,1000}/ nocase ascii wide
        // Description: pentester github username hosting exploitation tools
        // Reference: https://github.com/m8r0wn
        $string12 = /.{0,1000}\/m8r0wn\/.{0,1000}/ nocase ascii wide
        // Description: github repo hosting various exploitation tools
        // Reference: https://github.com/trustedsec
        $string13 = /.{0,1000}\/trustedsec\/.{0,1000}/ nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/x0rz
        $string14 = /.{0,1000}\/x0rz\/.{0,1000}/ nocase ascii wide
        // Description: redteam tools github repo 
        // Reference: https://github.com/cryptolok
        $string15 = /.{0,1000}\\cryptolok.{0,1000}/ nocase ascii wide
        // Description: Github username of pentester known for enumeration tools
        // Reference: https://github.com/aboul3la
        $string16 = /.{0,1000}aboul3la.{0,1000}/ nocase ascii wide
        // Description: This repo contains some Antimalware Scan Interface (AMSI) bypass / avoidance methods i found on different Blog Posts.
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string17 = /.{0,1000}Amsi\-Bypass.{0,1000}/ nocase ascii wide
        // Description: Open source testing tools for the SDR & security community
        // Reference: https://github.com/BastilleResearch
        $string18 = /.{0,1000}BastilleResearch.{0,1000}/ nocase ascii wide
        // Description: Cybersecurity Engineers and Offensive Security enthusiasts actively maintaining/updating Powershell Empire in our spare time.
        // Reference: https://github.com/BC-SECURITY
        $string19 = /.{0,1000}BC\-SECURITY.{0,1000}/ nocase ascii wide
        // Description: github username known for repos on passwords exploitation and offensive tools
        // Reference: https://github.com/berzerk0
        $string20 = /.{0,1000}berzerk0.{0,1000}/ nocase ascii wide
        // Description: This github account maps to the Black Hat Arsenal tools since its inception in 2011. For readibility. the tools are classified by category and not by session.
        // Reference: https://github.com/toolswatch/blackhat-arsenal-tools
        $string21 = /.{0,1000}blackhat\-arsenal\-tools.{0,1000}/ nocase ascii wide
        // Description: malware and offensive tools developper 
        // Reference: https://github.com/byt3bl33d3r
        $string22 = /.{0,1000}byt3bl33d3r.{0,1000}/ nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/Coalfire-Research
        $string23 = /.{0,1000}Coalfire\-Research.{0,1000}/ nocase ascii wide
        // Description: github user hosting malicious code and exploitation tools
        // Reference: https://github.com/curi0usJack
        $string24 = /.{0,1000}curi0usJack.{0,1000}/ nocase ascii wide
        // Description: Github user: A hacker. high&low-level coder and a lot of things between. An extremely curious creature loves to learn. Break things or make things that break things.
        // Reference: https://github.com/D4Vinci/
        $string25 = /.{0,1000}D4Vinci.{0,1000}/ nocase ascii wide
        // Description: Github user author of powershell obfuscation tools
        // Reference: https://github.com/danielbohannon
        $string26 = /.{0,1000}danielbohannon.{0,1000}/ nocase ascii wide
        // Description: github user name hosting exploitation tools:hacker. scripting. recon. OSINT. automation
        // Reference: https://github.com/dchrastil
        $string27 = /.{0,1000}dchrastil.{0,1000}/ nocase ascii wide
        // Description: Github Author of malicious scripts and eploitaiton tools 
        // Reference: https://github.com/deepzec
        $string28 = /.{0,1000}deepzec.{0,1000}/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/DominicBreuker
        $string29 = /.{0,1000}DominicBreuker.{0,1000}/ nocase ascii wide
        // Description: Github Author of malicious script and eploitaiton tools 
        // Reference: https://github.com/enigma0x3
        $string30 = /.{0,1000}enigma0x3.{0,1000}/ nocase ascii wide
        // Description: github username of hacker known for sniffing and spoofing exploitation tools
        // Reference: https://github.com/evilsocket
        $string31 = /.{0,1000}evilsocket.{0,1000}/ nocase ascii wide
        // Description: FortyNorth Security is a computer security consultancy specializing in offensive security work. We regularly perform red team assessments. pen tests. and more
        // Reference: https://github.com/FortyNorthSecurity
        $string32 = /.{0,1000}FortyNorthSecurity.{0,1000}/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/g0tmi1k
        $string33 = /.{0,1000}g0tmi1k.{0,1000}/ nocase ascii wide
        // Description: Github username known for exploitation toos and scripts
        // Reference: https://github.com/Arno0x
        $string34 = /.{0,1000}github\.com\/Arno0x.{0,1000}/ nocase ascii wide
        // Description: Private professional services firm providing offensive security testing to the Fortune 500. serving exploitation tools on github
        // Reference: https://github.com/BishopFox
        $string35 = /.{0,1000}github\.com\/BishopFox.{0,1000}/ nocase ascii wide
        // Description: Github user hosting exploitation tools for pentest and redteam
        // Reference: https://github.com/dafthack
        $string36 = /.{0,1000}github\.com\/dafthack.{0,1000}/ nocase ascii wide
        // Description: github repo name containing multiple exploitation tools
        // Reference: https://github.com/GoSecure
        $string37 = /.{0,1000}github\.com\/GoSecure.{0,1000}/ nocase ascii wide
        // Description: github repo name hosting securty tools and exploitation tools
        // Reference: https://github.com/nccgroup
        $string38 = /.{0,1000}github\.com\/nccgroup.{0,1000}/ nocase ascii wide
        // Description: An infosec security researcher & penetration tester. hosting offensive tools
        // Reference: https://github.com/quickbreach
        $string39 = /.{0,1000}github\.com\/quickbreach.{0,1000}/ nocase ascii wide
        // Description: github repo of orange cyberdefense red team
        // Reference: https://github.com/sensepost
        $string40 = /.{0,1000}github\.com\/sensepost.{0,1000}/ nocase ascii wide
        // Description: Welcome to the Infection Monkey! The Infection Monkey is an open source security tool for testing a data centers resiliency to perimeter breaches and internal server infection. The Monkey uses various methods to self propagate across a data center and reports success to a centralized Monkey Island server
        // Reference: https://github.com/h0nus
        $string41 = /.{0,1000}guardicore.{0,1000}monkey.{0,1000}/ nocase ascii wide
        // Description: An Open Source Hacking Tools database
        // Reference: https://github.com/Hack-with-Github
        $string42 = /.{0,1000}Hack\-with\-Github.{0,1000}/ nocase ascii wide
        // Description: powershell forensic tools
        // Reference: https://github.com/Invoke-IR
        $string43 = /.{0,1000}Invoke\-IR.{0,1000}/ nocase ascii wide
        // Description: gthub username hosting malware samples and exploitation tools
        // Reference: https://github.com/itsKindred
        $string44 = /.{0,1000}itsKindred.{0,1000}/ nocase ascii wide
        // Description: github username. a knack for cryptography. computer vision. opensource software and infosec. hosting infosec tools used by pentester
        // Reference: https://github.com/jedisct1
        $string45 = /.{0,1000}jedisct1.{0,1000}/ nocase ascii wide
        // Description: github repo name containing multiple tools for log exploitation
        // Reference: https://github.com/JPCERTCC
        $string46 = /.{0,1000}JPCERTCC.{0,1000}/ nocase ascii wide
        // Description: github repo name hosting windows kernel exploits
        // Reference: https://github.com/SecWiki/windows-kernel-exploits
        $string47 = /.{0,1000}kernel\-exploits.{0,1000}/ nocase ascii wide
        // Description: username Kuba Gretzky hosting sniffing and spoofing exploitation tools
        // Reference: https://github.com/kgretzky
        $string48 = /.{0,1000}kgretzky.{0,1000}/ nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/khast3x
        $string49 = /.{0,1000}khast3x.{0,1000}/ nocase ascii wide
        // Description: exploitation tools for attackers
        // Reference: https://github.com/klsecservices
        $string50 = /.{0,1000}klsecservices.{0,1000}/ nocase ascii wide
        // Description: github username. creator of patator and exploitation tools
        // Reference: https://github.com/lanjelot
        $string51 = /.{0,1000}lanjelot.{0,1000}/ nocase ascii wide
        // Description: github repo name hosting exploitation tools
        // Reference: https://github.com/leapsecurity
        $string52 = /.{0,1000}leapsecurity.{0,1000}/ nocase ascii wide
        // Description: Github username of hacker known for malware pocs and  windows exploitations
        // Reference: https://github.com/LordNoteworthy
        $string53 = /.{0,1000}LordNoteworthy.{0,1000}/ nocase ascii wide
        // Description: github username hosting offensive tools 
        // Reference: https://github.com/matterpreter
        $string54 = /.{0,1000}matterpreter.{0,1000}/ nocase ascii wide
        // Description: MDSecs ActiveBreach Team. own a github repo with lots of exploitation tools https://www.mdsec.co.uk/services/red-teaming/
        // Reference: https://github.com/mdsecactivebreach/
        $string55 = /.{0,1000}mdsecactivebreach.{0,1000}/ nocase ascii wide
        // Description: MOGWAI LABS is an infosec boutique with a strong emphasis on offensive security github repo hosting offensive tools
        // Reference: https://github.com/mogwailabs
        $string56 = /.{0,1000}mogwailabs.{0,1000}/ nocase ascii wide
        // Description: github repo that was hosting exploitation tools. may be used by other exploitation tools 
        // Reference: https://github.com/MooseDojo
        $string57 = /.{0,1000}MooseDojo.{0,1000}/ nocase ascii wide
        // Description: github username Mostly Red Team tools for penetration testing. Twitter - @MrUn1k0d3r
        // Reference: https://github.com/Mr-Un1k0d3r
        $string58 = /.{0,1000}Mr\-Un1k0d3r.{0,1000}/ nocase ascii wide
        // Description: used to be a malware repo aso hosting exploitation tools
        // Reference: https://github.com/mwrlabs
        $string59 = /.{0,1000}mwrlabs.{0,1000}/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/n1nj4sec
        $string60 = /.{0,1000}n1nj4sec.{0,1000}/ nocase ascii wide
        // Description: author of RAT tools on github
        // Reference: https://github.com/neoneggplant
        $string61 = /.{0,1000}neoneggplant.{0,1000}/ nocase ascii wide
        // Description: Author of APT simulator
        // Reference: https://github.com/NextronSystems
        $string62 = /.{0,1000}NextronSystems.{0,1000}/ nocase ascii wide
        // Description: github user hosting exploitation and recon tools
        // Reference: https://github.com/nyxgeek
        $string63 = /.{0,1000}nyxgeek.{0,1000}/ nocase ascii wide
        // Description: resources for pentesters
        // Reference: https://github.com/obscuritylabs
        $string64 = /.{0,1000}obscuritylabs.{0,1000}/ nocase ascii wide
        // Description: github repo name hosting lots of exploitation tools
        // Reference: https://github.com/P0cL4bs
        $string65 = /.{0,1000}P0cL4bs.{0,1000}/ nocase ascii wide
        // Description: github repo name - privileges exploitation and offensive tools
        // Reference: https://github.com/pentestmonkey
        $string66 = /.{0,1000}pentestmonkey.{0,1000}/ nocase ascii wide
        // Description: Pentest hosting multiple offensive tools
        // Reference: https://github.com/r00t-3xp10it
        $string67 = /.{0,1000}r00t\-3xp10it.{0,1000}/ nocase ascii wide
        // Description: github user author of various offensive tools
        // Reference: https://github.com/rasta-mouse
        $string68 = /.{0,1000}rasta\-mouse.{0,1000}/ nocase ascii wide
        // Description: github user Security Researcher @F5Networks hosting reverse tools and other pentester tools for data exfiltration and password attacks
        // Reference: https://github.com/realgam3
        $string69 = /.{0,1000}realgam3.{0,1000}/ nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/RedTeamOperations
        $string70 = /.{0,1000}RedTeamOperations.{0,1000}/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/s0lst1c3
        $string71 = /.{0,1000}s0lst1c3.{0,1000}/ nocase ascii wide
        // Description: github username hosting offensive tools. mostly for web hacking
        // Reference: https://github.com/s0md3v
        $string72 = /.{0,1000}s0md3v.{0,1000}/ nocase ascii wide
        // Description: Github username of hackr known for exploitation scripts Pentesting. scripting and pwning!
        // Reference: https://github.com/S3cur3Th1sSh1t
        $string73 = /.{0,1000}S3cur3Th1sSh1t.{0,1000}/ nocase ascii wide
        // Description: s7scan is a tool that scans networks. enumerates Siemens PLCs and gathers basic information about them. such as PLC firmware and hardwaare version. network configuration and security parameters. It is completely written on Python.
        // Reference: https://github.com/klsecservices/s7scan
        $string74 = /.{0,1000}s7scan.{0,1000}/ nocase ascii wide
        // Description: github username hosting exploitation tools
        // Reference: https://github.com/sailay1996
        $string75 = /.{0,1000}sailay1996.{0,1000}/ nocase ascii wide
        // Description: github username - Pentester. Red teamer. OSCP. Former wardialer and OKI 900 enthusiast. Senior Security Consultant @ctxis hosting offensve tools
        // Reference: https://github.com/sc0tfree
        $string76 = /.{0,1000}sc0tfree.{0,1000}/ nocase ascii wide
        // Description: github username hosting post exploitation tools
        // Reference: https://github.com/Screetsec
        $string77 = /.{0,1000}Screetsec.{0,1000}/ nocase ascii wide
        // Description: github username hosting  exploitation tools
        // Reference: https://github.com/secgroundzero
        $string78 = /.{0,1000}secgroundzero.{0,1000}/ nocase ascii wide
        // Description: github username hosting process injection codes 
        // Reference: https://github.com/secrary
        $string79 = /.{0,1000}secrary.{0,1000}/ nocase ascii wide
        // Description: pentest documentations
        // Reference: https://github.com/securitywithoutborders
        $string80 = /.{0,1000}securitywithoutborders.{0,1000}/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/SilverPoision
        $string81 = /.{0,1000}SilverPoision.{0,1000}/ nocase ascii wide
        // Description: github repo Open source IT security software tools and information and exploitation tools
        // Reference: https://github.com/SySS-Research
        $string82 = /.{0,1000}SySS\-Research.{0,1000}/ nocase ascii wide
        // Description: github repo hosting post exploitation tools
        // Reference: https://github.com/threatexpress
        $string83 = /.{0,1000}threatexpress.{0,1000}/ nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/tiagorlampert
        $string84 = /.{0,1000}tiagorlampert.{0,1000}/ nocase ascii wide
        // Description: github repo hosting offensive tools and exploitation frameworks
        // Reference: https://github.com/True-Demon
        $string85 = /.{0,1000}True\-Demon.{0,1000}/ nocase ascii wide
        // Description: github repo hosting sniffing spoofing and data exfiltration tools
        // Reference: https://github.com/TryCatchHCF
        $string86 = /.{0,1000}TryCatchHCF.{0,1000}/ nocase ascii wide
        // Description: github repo hosting offensive tools and exploitation frameworks
        // Reference: https://github.com/Und3rf10w
        $string87 = /.{0,1000}Und3rf10w.{0,1000}/ nocase ascii wide
        // Description: github repo hosting obfuscation tools
        // Reference: https://github.com/unixpickle
        $string88 = /.{0,1000}unixpickle.{0,1000}/ nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/virajkulkarni14
        $string89 = /.{0,1000}virajkulkarni14.{0,1000}/ nocase ascii wide
        // Description: github username hosting post exploitation tools and recon tools
        // Reference: https://github.com/Viralmaniar
        $string90 = /.{0,1000}Viralmaniar.{0,1000}/ nocase ascii wide
        // Description: github username hosting red team tools
        // Reference: https://github.com/vysecurity
        $string91 = /.{0,1000}vysecurity.{0,1000}/ nocase ascii wide
        // Description: Github username known for password exploitation and offensive tools
        // Reference: https://github.com/x90skysn3k
        $string92 = /.{0,1000}x90skysn3k.{0,1000}/ nocase ascii wide
        // Description: github repo username hosting red team tools
        // Reference: https://github.com/xillwillx
        $string93 = /.{0,1000}xillwillx.{0,1000}/ nocase ascii wide
        // Description: github username hosting obfuscation and exploitation tools
        // Reference: https://github.com/xoreaxeaxeax
        $string94 = /.{0,1000}xoreaxeaxeax.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
