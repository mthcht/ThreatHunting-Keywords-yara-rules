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
        $string1 = /\/attackercan\// nocase ascii wide
        // Description: Github username of known powershell offensive modules and scripts
        // Reference: https://github.com/Ben0xA
        $string2 = /\/Ben0xA\// nocase ascii wide
        // Description: Github username known for exploitation tools. Web application security researcher. Current Location: Moscow. Russia
        // Reference: https://github.com/Bo0oM
        $string3 = /\/Bo0oM/ nocase ascii wide
        // Description: Github username known for network exploitation tools
        // Reference: https://github.com/chrisk44/Hijacker
        $string4 = /\/chrisk44\// nocase ascii wide
        // Description: Github username Red teamer @ Outflank. Passionate about networking and cybersecurity.  known for exploitation tools dev
        // Reference: https://github.com/Cn33liz
        $string5 = /\/Cn33liz/ nocase ascii wide
        // Description: Github username Red teamer @ Outflank.Passionate about networking and cybersecurity. known for exploitation tools dev
        // Reference: https://twitter.com/Cneelis
        $string6 = /\/Cneelis/ nocase ascii wide
        // Description: Zero day code injection and vulnerabilities github repo
        // Reference: https://github.com/Cybellum
        $string7 = /\/Cybellum/ nocase ascii wide
        // Description: pentest tools repo
        // Reference: https://github.com/CyDefUnicorn
        $string8 = /\/CyDefUnicorn/ nocase ascii wide
        // Description: Co-founder of Empire. BloodHound. and the Veil-Framework | PowerSploit developer | krb lover | Microsoft PowerShell MVP | Security at the misfortune of others
        // Reference: https://github.com/HarmJ0y
        $string9 = /\/HarmJ0y/ nocase ascii wide
        // Description: github username. 'My name is Halil Dalabasmaz. I consider myself Pwner.' containing exploitation tools
        // Reference: https://github.com/hlldz
        $string10 = /\/hlldz/ nocase ascii wide
        // Description: github username 'hacker' hosting exploitaitont tools and passwords attacks tools
        // Reference: https://github.com/m4ll0k
        $string11 = /\/m4ll0k\// nocase ascii wide
        // Description: pentester github username hosting exploitation tools
        // Reference: https://github.com/m8r0wn
        $string12 = /\/m8r0wn\// nocase ascii wide
        // Description: github repo hosting various exploitation tools
        // Reference: https://github.com/trustedsec
        $string13 = /\/trustedsec\// nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/x0rz
        $string14 = /\/x0rz\// nocase ascii wide
        // Description: redteam tools github repo 
        // Reference: https://github.com/cryptolok
        $string15 = /\\cryptolok/ nocase ascii wide
        // Description: Github username of pentester known for enumeration tools
        // Reference: https://github.com/aboul3la
        $string16 = /aboul3la/ nocase ascii wide
        // Description: This repo contains some Antimalware Scan Interface (AMSI) bypass / avoidance methods i found on different Blog Posts.
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string17 = /Amsi\-Bypass/ nocase ascii wide
        // Description: Open source testing tools for the SDR & security community
        // Reference: https://github.com/BastilleResearch
        $string18 = /BastilleResearch/ nocase ascii wide
        // Description: Cybersecurity Engineers and Offensive Security enthusiasts actively maintaining/updating Powershell Empire in our spare time.
        // Reference: https://github.com/BC-SECURITY
        $string19 = /BC\-SECURITY/ nocase ascii wide
        // Description: github username known for repos on passwords exploitation and offensive tools
        // Reference: https://github.com/berzerk0
        $string20 = /berzerk0/ nocase ascii wide
        // Description: This github account maps to the Black Hat Arsenal tools since its inception in 2011. For readibility. the tools are classified by category and not by session.
        // Reference: https://github.com/toolswatch/blackhat-arsenal-tools
        $string21 = /blackhat\-arsenal\-tools/ nocase ascii wide
        // Description: malware and offensive tools developper 
        // Reference: https://github.com/byt3bl33d3r
        $string22 = /byt3bl33d3r/ nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/Coalfire-Research
        $string23 = /Coalfire\-Research/ nocase ascii wide
        // Description: github user hosting malicious code and exploitation tools
        // Reference: https://github.com/curi0usJack
        $string24 = /curi0usJack/ nocase ascii wide
        // Description: Github user: A hacker. high&low-level coder and a lot of things between. An extremely curious creature loves to learn. Break things or make things that break things.
        // Reference: https://github.com/D4Vinci/
        $string25 = /D4Vinci/ nocase ascii wide
        // Description: Github user author of powershell obfuscation tools
        // Reference: https://github.com/danielbohannon
        $string26 = /danielbohannon/ nocase ascii wide
        // Description: github user name hosting exploitation tools:hacker. scripting. recon. OSINT. automation
        // Reference: https://github.com/dchrastil
        $string27 = /dchrastil/ nocase ascii wide
        // Description: Github Author of malicious scripts and eploitaiton tools 
        // Reference: https://github.com/deepzec
        $string28 = /deepzec/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/DominicBreuker
        $string29 = /DominicBreuker/ nocase ascii wide
        // Description: Github Author of malicious script and eploitaiton tools 
        // Reference: https://github.com/enigma0x3
        $string30 = /enigma0x3/ nocase ascii wide
        // Description: github username of hacker known for sniffing and spoofing exploitation tools
        // Reference: https://github.com/evilsocket
        $string31 = /evilsocket/ nocase ascii wide
        // Description: FortyNorth Security is a computer security consultancy specializing in offensive security work. We regularly perform red team assessments. pen tests. and more
        // Reference: https://github.com/FortyNorthSecurity
        $string32 = /FortyNorthSecurity/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/g0tmi1k
        $string33 = /g0tmi1k/ nocase ascii wide
        // Description: Github username known for exploitation toos and scripts
        // Reference: https://github.com/Arno0x
        $string34 = /github\.com\/Arno0x/ nocase ascii wide
        // Description: Private professional services firm providing offensive security testing to the Fortune 500. serving exploitation tools on github
        // Reference: https://github.com/BishopFox
        $string35 = /github\.com\/BishopFox/ nocase ascii wide
        // Description: Github user hosting exploitation tools for pentest and redteam
        // Reference: https://github.com/dafthack
        $string36 = /github\.com\/dafthack/ nocase ascii wide
        // Description: github repo name containing multiple exploitation tools
        // Reference: https://github.com/GoSecure
        $string37 = /github\.com\/GoSecure/ nocase ascii wide
        // Description: github repo name hosting securty tools and exploitation tools
        // Reference: https://github.com/nccgroup
        $string38 = /github\.com\/nccgroup/ nocase ascii wide
        // Description: An infosec security researcher & penetration tester. hosting offensive tools
        // Reference: https://github.com/quickbreach
        $string39 = /github\.com\/quickbreach/ nocase ascii wide
        // Description: github repo of orange cyberdefense red team
        // Reference: https://github.com/sensepost
        $string40 = /github\.com\/sensepost/ nocase ascii wide
        // Description: Welcome to the Infection Monkey! The Infection Monkey is an open source security tool for testing a data centers resiliency to perimeter breaches and internal server infection. The Monkey uses various methods to self propagate across a data center and reports success to a centralized Monkey Island server
        // Reference: https://github.com/h0nus
        $string41 = /guardicore.*monkey/ nocase ascii wide
        // Description: An Open Source Hacking Tools database
        // Reference: https://github.com/Hack-with-Github
        $string42 = /Hack\-with\-Github/ nocase ascii wide
        // Description: powershell forensic tools
        // Reference: https://github.com/Invoke-IR
        $string43 = /Invoke\-IR/ nocase ascii wide
        // Description: gthub username hosting malware samples and exploitation tools
        // Reference: https://github.com/itsKindred
        $string44 = /itsKindred/ nocase ascii wide
        // Description: github username. a knack for cryptography. computer vision. opensource software and infosec. hosting infosec tools used by pentester
        // Reference: https://github.com/jedisct1
        $string45 = /jedisct1/ nocase ascii wide
        // Description: github repo name containing multiple tools for log exploitation
        // Reference: https://github.com/JPCERTCC
        $string46 = /JPCERTCC/ nocase ascii wide
        // Description: github repo name hosting windows kernel exploits
        // Reference: https://github.com/SecWiki/windows-kernel-exploits
        $string47 = /kernel\-exploits/ nocase ascii wide
        // Description: username Kuba Gretzky hosting sniffing and spoofing exploitation tools
        // Reference: https://github.com/kgretzky
        $string48 = /kgretzky/ nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/khast3x
        $string49 = /khast3x/ nocase ascii wide
        // Description: exploitation tools for attackers
        // Reference: https://github.com/klsecservices
        $string50 = /klsecservices/ nocase ascii wide
        // Description: github username. creator of patator and exploitation tools
        // Reference: https://github.com/lanjelot
        $string51 = /lanjelot/ nocase ascii wide
        // Description: github repo name hosting exploitation tools
        // Reference: https://github.com/leapsecurity
        $string52 = /leapsecurity/ nocase ascii wide
        // Description: Github username of hacker known for malware pocs and  windows exploitations
        // Reference: https://github.com/LordNoteworthy
        $string53 = /LordNoteworthy/ nocase ascii wide
        // Description: github username hosting offensive tools 
        // Reference: https://github.com/matterpreter
        $string54 = /matterpreter/ nocase ascii wide
        // Description: MDSecs ActiveBreach Team. own a github repo with lots of exploitation tools https://www.mdsec.co.uk/services/red-teaming/
        // Reference: https://github.com/mdsecactivebreach/
        $string55 = /mdsecactivebreach/ nocase ascii wide
        // Description: MOGWAI LABS is an infosec boutique with a strong emphasis on offensive security github repo hosting offensive tools
        // Reference: https://github.com/mogwailabs
        $string56 = /mogwailabs/ nocase ascii wide
        // Description: github repo that was hosting exploitation tools. may be used by other exploitation tools 
        // Reference: https://github.com/MooseDojo
        $string57 = /MooseDojo/ nocase ascii wide
        // Description: github username Mostly Red Team tools for penetration testing. Twitter - @MrUn1k0d3r
        // Reference: https://github.com/Mr-Un1k0d3r
        $string58 = /Mr\-Un1k0d3r/ nocase ascii wide
        // Description: used to be a malware repo aso hosting exploitation tools
        // Reference: https://github.com/mwrlabs
        $string59 = /mwrlabs/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/n1nj4sec
        $string60 = /n1nj4sec/ nocase ascii wide
        // Description: author of RAT tools on github
        // Reference: https://github.com/neoneggplant
        $string61 = /neoneggplant/ nocase ascii wide
        // Description: Author of APT simulator
        // Reference: https://github.com/NextronSystems
        $string62 = /NextronSystems/ nocase ascii wide
        // Description: github user hosting exploitation and recon tools
        // Reference: https://github.com/nyxgeek
        $string63 = /nyxgeek/ nocase ascii wide
        // Description: resources for pentesters
        // Reference: https://github.com/obscuritylabs
        $string64 = /obscuritylabs/ nocase ascii wide
        // Description: github repo name hosting lots of exploitation tools
        // Reference: https://github.com/P0cL4bs
        $string65 = /P0cL4bs/ nocase ascii wide
        // Description: github repo name - privileges exploitation and offensive tools
        // Reference: https://github.com/pentestmonkey
        $string66 = /pentestmonkey/ nocase ascii wide
        // Description: Pentest hosting multiple offensive tools
        // Reference: https://github.com/r00t-3xp10it
        $string67 = /r00t\-3xp10it/ nocase ascii wide
        // Description: github user author of various offensive tools
        // Reference: https://github.com/rasta-mouse
        $string68 = /rasta\-mouse/ nocase ascii wide
        // Description: github user Security Researcher @F5Networks hosting reverse tools and other pentester tools for data exfiltration and password attacks
        // Reference: https://github.com/realgam3
        $string69 = /realgam3/ nocase ascii wide
        // Description: Red team exploitation tools 
        // Reference: https://github.com/RedTeamOperations
        $string70 = /RedTeamOperations/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/s0lst1c3
        $string71 = /s0lst1c3/ nocase ascii wide
        // Description: github username hosting offensive tools. mostly for web hacking
        // Reference: https://github.com/s0md3v
        $string72 = /s0md3v/ nocase ascii wide
        // Description: Github username of hackr known for exploitation scripts Pentesting. scripting and pwning!
        // Reference: https://github.com/S3cur3Th1sSh1t
        $string73 = /S3cur3Th1sSh1t/ nocase ascii wide
        // Description: s7scan is a tool that scans networks. enumerates Siemens PLCs and gathers basic information about them. such as PLC firmware and hardwaare version. network configuration and security parameters. It is completely written on Python.
        // Reference: https://github.com/klsecservices/s7scan
        $string74 = /s7scan/ nocase ascii wide
        // Description: github username hosting exploitation tools
        // Reference: https://github.com/sailay1996
        $string75 = /sailay1996/ nocase ascii wide
        // Description: github username - Pentester. Red teamer. OSCP. Former wardialer and OKI 900 enthusiast. Senior Security Consultant @ctxis hosting offensve tools
        // Reference: https://github.com/sc0tfree
        $string76 = /sc0tfree/ nocase ascii wide
        // Description: github username hosting post exploitation tools
        // Reference: https://github.com/Screetsec
        $string77 = /Screetsec/ nocase ascii wide
        // Description: github username hosting  exploitation tools
        // Reference: https://github.com/secgroundzero
        $string78 = /secgroundzero/ nocase ascii wide
        // Description: github username hosting process injection codes 
        // Reference: https://github.com/secrary
        $string79 = /secrary/ nocase ascii wide
        // Description: pentest documentations
        // Reference: https://github.com/securitywithoutborders
        $string80 = /securitywithoutborders/ nocase ascii wide
        // Description: Github username hosting exploitation tools
        // Reference: https://github.com/SilverPoision
        $string81 = /SilverPoision/ nocase ascii wide
        // Description: github repo Open source IT security software tools and information and exploitation tools
        // Reference: https://github.com/SySS-Research
        $string82 = /SySS\-Research/ nocase ascii wide
        // Description: github repo hosting post exploitation tools
        // Reference: https://github.com/threatexpress
        $string83 = /threatexpress/ nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/tiagorlampert
        $string84 = /tiagorlampert/ nocase ascii wide
        // Description: github repo hosting offensive tools and exploitation frameworks
        // Reference: https://github.com/True-Demon
        $string85 = /True\-Demon/ nocase ascii wide
        // Description: github repo hosting sniffing spoofing and data exfiltration tools
        // Reference: https://github.com/TryCatchHCF
        $string86 = /TryCatchHCF/ nocase ascii wide
        // Description: github repo hosting offensive tools and exploitation frameworks
        // Reference: https://github.com/Und3rf10w
        $string87 = /Und3rf10w/ nocase ascii wide
        // Description: github repo hosting obfuscation tools
        // Reference: https://github.com/unixpickle
        $string88 = /unixpickle/ nocase ascii wide
        // Description: github repo username hosting exploitation tools
        // Reference: https://github.com/virajkulkarni14
        $string89 = /virajkulkarni14/ nocase ascii wide
        // Description: github username hosting post exploitation tools and recon tools
        // Reference: https://github.com/Viralmaniar
        $string90 = /Viralmaniar/ nocase ascii wide
        // Description: github username hosting red team tools
        // Reference: https://github.com/vysecurity
        $string91 = /vysecurity/ nocase ascii wide
        // Description: Github username known for password exploitation and offensive tools
        // Reference: https://github.com/x90skysn3k
        $string92 = /x90skysn3k/ nocase ascii wide
        // Description: github repo username hosting red team tools
        // Reference: https://github.com/xillwillx
        $string93 = /xillwillx/ nocase ascii wide
        // Description: github username hosting obfuscation and exploitation tools
        // Reference: https://github.com/xoreaxeaxeax
        $string94 = /xoreaxeaxeax/ nocase ascii wide

    condition:
        any of them
}