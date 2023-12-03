rule exegol
{
    meta:
        description = "Detection patterns for the tool 'exegol' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exegol"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string1 = /.{0,1000}\s\/\.exegol\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string2 = /.{0,1000}\sASREProastables\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string3 = /.{0,1000}\sASREProastables\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string4 = /.{0,1000}\s\-\-attack\spartial_d\s\-\-key\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string5 = /.{0,1000}\s\-\-attack\spartial_q\s\-\-key\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string6 = /.{0,1000}\s\-\-basic\s\"FUZZ:FUZ2Z\".{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string7 = /.{0,1000}\s\-\-convert_idrsa_pub\s\-\-publickey\s\$HOME\/\.ssh\/id_rsa\.pub.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string8 = /.{0,1000}\s\-\-createpub\s\-n\s7828374823761928712873129873981723\.\.\.12837182\s\-e\s65537.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string9 = /.{0,1000}\s\-d\s.{0,1000}\s\-dc\s.{0,1000}\s\-nu\s\'neo4j\'\s\-np\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string10 = /.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-listener\s.{0,1000}\s\-\-target\s.{0,1000}\$DC_HOST.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string11 = /.{0,1000}\s\-\-deauth\s.{0,1000}\s\-a\sTR:GT:AP:BS:SS:ID\swlan.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string12 = /.{0,1000}\sdeepce\.sh\s.{0,1000}\-\-install.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string13 = /.{0,1000}\s\-enabled\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-old\-bloodhound.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string14 = /.{0,1000}\sexegol\.apk.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string15 = /.{0,1000}\sexegol\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string16 = /.{0,1000}\s\-\-file\sownedusers\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string17 = /.{0,1000}\s\-\-hash\-type\s.{0,1000}\s\-\-attack\-mode\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string18 = /.{0,1000}\s\-\-host\s.{0,1000}\s\-\-port\s.{0,1000}\s\-\-executable\s.{0,1000}\.exe\s\-\-command\s.{0,1000}cmd\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string19 = /.{0,1000}\sinstall\sevil\-winrm.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string20 = /.{0,1000}\s\-\-interface\s.{0,1000}\s\-\-analyze\s\-\-disable\-ess.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string21 = /.{0,1000}\s\-\-interface\s.{0,1000}\s\-\-analyze\s\-\-lm\s\-\-disable\-ess.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string22 = /.{0,1000}\s\-\-isroca\s\-\-publickey\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string23 = /.{0,1000}\s\-just\-dc\-user\s\'krbtgt\'\s\-dc\-ip\s\s.{0,1000}\s\-k\s\-no\-pass\s\@.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string24 = /.{0,1000}\sKerberoastables\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string25 = /.{0,1000}\skerberos\stgt\s.{0,1000}kerberos\+rc4:\/\/.{0,1000}:.{0,1000}\@.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string26 = /.{0,1000}\s\-\-key\sexamples\/conspicuous\.priv\s\-\-isconspicuous.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string27 = /.{0,1000}\s\-\-krbpass\s.{0,1000}\s\-\-krbsalt\s.{0,1000}\s\-t\s.{0,1000}\s\-\-escalate\-user\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string28 = /.{0,1000}\slinpeas\.sh.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string29 = /.{0,1000}\s\-\-lport\s1337\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string30 = /.{0,1000}\slsa\sminidump\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string31 = /.{0,1000}\slsass_creds\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string32 = /.{0,1000}\slsassy\s\-k\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string33 = /.{0,1000}\smoodlescan\s\-r\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string34 = /.{0,1000}\s\-ntds\sntds\.dit\.save\s\-system\ssystem\.save\sLOCAL.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string35 = /.{0,1000}\s\-nthash\s.{0,1000}\s\-spn\s.{0,1000}\s\-domain\-sid\s.{0,1000}\s\-domain\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string36 = /.{0,1000}\s\-nthash\s.{0,1000}\-domain\-sid\sS\-1\-5\-11\-39129514\-1145628974\-103568174\s\-domain.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string37 = /.{0,1000}\sntlmv1\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string38 = /.{0,1000}\s\-\-outdir\sldapdomaindump\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string39 = /.{0,1000}\s\-\-plugin\sKeeFarceRebornPlugin\.dll.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string40 = /.{0,1000}\s\-\-publickey\s.{0,1000}\s\-\-ecmdigits\s25\s\-\-verbose\s\-\-private.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string41 = /.{0,1000}\s\-\-publickey\s.{0,1000}\s\-\-uncipherfile\s\.\/ciphered\\_file.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string42 = /.{0,1000}\spywsus\.py\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string43 = /.{0,1000}\sreq\s\-username\s.{0,1000}\s\-p\s.{0,1000}\s\-ca\s.{0,1000}\s\-target\s.{0,1000}\s\-template\s.{0,1000}\s\-upn\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string44 = /.{0,1000}\s\-request\s\-format\shashcat\s\-outputfile\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string45 = /.{0,1000}\s\-\-requirement\s.{0,1000}Exegol\/requirements\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string46 = /.{0,1000}\s\-s\s.{0,1000}\s\-\-method\s1\s\-\-function\sshell_exec\s\-\-parameters\scmd:id.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string47 = /.{0,1000}\s\-\-script\sdns\-srv\-enum\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string48 = /.{0,1000}\s\-\-script\shttp\-ntlm\-info\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string49 = /.{0,1000}\s\-\-script\ssmb\-enum\-shares\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string50 = /.{0,1000}\s\-\-script\=ldap\-search\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string51 = /.{0,1000}\s\-\-script\=realvnc\-auth\-bypass\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string52 = /.{0,1000}\s\-\-script\-args\sdns\-srv\-enum\.domain\=.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string53 = /.{0,1000}\s\-\-set\-as\-owned\ssmart\s\-bp\s.{0,1000}\skerberos\s.{0,1000}\s\-\-kdc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string54 = /.{0,1000}\s\-\-shell\stcsh\sexegol.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string55 = /.{0,1000}\s\-t\sdcsync:\/\/.{0,1000}\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string56 = /.{0,1000}\stargetedKerberoast\.py\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string57 = /.{0,1000}\stheHarvester\.py\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string58 = /.{0,1000}\suberfile\.py\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string59 = /.{0,1000}\s\-\-wpad\s\-\-lm\s\-\-ProxyAuth\s\-\-disable\-ess.{0,1000}.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string60 = /.{0,1000}\.py\s\-aesKey\s\"9ff86898afa70f5f7b9f2bf16320cb38edb2639409e1bc441ac417fac1fed5ab\".{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string61 = /.{0,1000}\.py\s\-\-zip\s\-c\sAll\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-\-hashes\s\'ffffffffffffffffffffffffffffffff\':.{0,1000}\s\-dc\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string62 = /.{0,1000}\/\.cme\/cme\.conf.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string63 = /.{0,1000}\/\.exegol\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string64 = /.{0,1000}\/ASREProastables\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string65 = /.{0,1000}\/AzureHound\.ps1.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string66 = /.{0,1000}\/bash_completion\.d\/exegol.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string67 = /.{0,1000}\/completions\/exegol\.fish.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string68 = /.{0,1000}\/CrackMapExec\.git/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string69 = /.{0,1000}\/crackmapexec\/cme\.conf.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string70 = /.{0,1000}\/darkweb2017\-top100\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string71 = /.{0,1000}\/deepce\.sh\s.{0,1000}\-\-install.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string72 = /.{0,1000}\/exegol\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string73 = /.{0,1000}\/exegol_user_sources\.list.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string74 = /.{0,1000}\/exegol\-docker\-build\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string75 = /.{0,1000}\/Exegol\-history\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string76 = /.{0,1000}\/Exegol\-images\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string77 = /.{0,1000}\/Exegol\-images\.git.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string78 = /.{0,1000}\/linpeas\.sh.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string79 = /.{0,1000}\/metasploit\-framework\/embedded\/framework.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string80 = /.{0,1000}\/ntlmv1\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string81 = /.{0,1000}\/opt\/\.exegol_aliases.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string82 = /.{0,1000}\/opt\/seclists\/Discovery\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string83 = /.{0,1000}\/Plazmaz\/LNKUp.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string84 = /.{0,1000}\/pywsus\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string85 = /.{0,1000}\/Responder\/Responder\.conf.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string86 = /.{0,1000}\/root\/\.mozilla\/firefox\/.{0,1000}\.Exegol.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string87 = /.{0,1000}\/shadowcoerce\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string88 = /.{0,1000}\/targetedKerberoast\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string89 = /.{0,1000}\/theHarvester\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string90 = /.{0,1000}\/tmp\/metasploit_install.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string91 = /.{0,1000}\/top\-usernames\-shortlist\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string92 = /.{0,1000}\/uberfile\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string93 = /.{0,1000}\/usr\/local\/bin\/exegol.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string94 = /.{0,1000}\/var\/log\/exegol\/.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string95 = /.{0,1000}:\'123pentest\'.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string96 = /.{0,1000}\\AzureHound\.ps1.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string97 = /.{0,1000}\\Exegol\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string98 = /.{0,1000}\\exegol\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string99 = /.{0,1000}\\Exegol\-images\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string100 = /.{0,1000}\\Exegol\-images\-.{0,1000}\\.{0,1000}docker.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string101 = /.{0,1000}\\pywsus\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string102 = /.{0,1000}\\shadowcoerce\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string103 = /.{0,1000}\\uberfile\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string104 = /.{0,1000}aclpwn\s\-f\s.{0,1000}\s\-ft\scomputer\s\-t\s.{0,1000}\s\-tt\sdomain\s\-d\s.{0,1000}\s\-dry.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string105 = /.{0,1000}addcomputer\.py\s\-computer\-name\s.{0,1000}\s\-computer\-pass\s.{0,1000}\s\-dc\-host\s.{0,1000}\s\-domain\-netbios\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string106 = /.{0,1000}addcomputer\.py\s\-delete\s\-computer\-name\s.{0,1000}\s\-dc\-host\s.{0,1000}\s\-domain\-netbios\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string107 = /.{0,1000}addspn\.py\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-t\s.{0,1000}\s\-s\s.{0,1000}\s\-\-additional\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string108 = /.{0,1000}adidnsdump\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string109 = /.{0,1000}aireplay\-ng\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string110 = /.{0,1000}aireplay\-ng\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string111 = /.{0,1000}airodump\-ng\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string112 = /.{0,1000}amass\senum\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string113 = /.{0,1000}avrdude\s\-c\susbasp\s\-p\sm328p\s\-U\sflash:w:avr\.hex.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string114 = /.{0,1000}aws\sconfigure\s\-\-profile\sexegol.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string115 = /.{0,1000}bettercap\s\-iface\seth0.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string116 = /.{0,1000}binwalk\s\-e\simage\.png.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string117 = /.{0,1000}bloodhound\s\&\>\s\/dev\/null\s\&.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string118 = /.{0,1000}bloodhound\-import\s\-du\sneo4j\s\-dp\s.{0,1000}\.json.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string119 = /.{0,1000}bloodhound\-quickwin\s\-u\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string120 = /.{0,1000}bruteforce\-luks\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string121 = /.{0,1000}bruteforce\-luks\s\-t\s4\s\-l\s5\s\-m\s5\s\/dev\/sdb1.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string122 = /.{0,1000}bully\swlan1mon\s\-b\s.{0,1000}\s\-c\s9\s\-S\s\-F\s\-B\s\-v\s3.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string123 = /.{0,1000}buster\s\-e\s.{0,1000}\s\-f\sjohn\s\-l\sdoe\s\-b\s\'.{0,1000}.{0,1000}.{0,1000}.{0,1000}1989\'.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string124 = /.{0,1000}byt3bl33d3r\/pth\-toolkit.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string125 = /.{0,1000}calebstewart\/pwncat.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string126 = /.{0,1000}cat\sdomains\.txt\s\|\sdnsx\s\-silent\s\-w\sjira.{0,1000}grafana.{0,1000}jenkins\s\-d\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string127 = /.{0,1000}certipy\sfind\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string128 = /.{0,1000}certipy\srelay\s\-ca\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string129 = /.{0,1000}certipy\sreq\s\-username\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string130 = /.{0,1000}certsync\s\-u\s.{0,1000}\s\-p\s.{0,1000}\-d\s.{0,1000}\s\-ca\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string131 = /.{0,1000}cewl\s\-\-depth\s.{0,1000}\s\-\-with\-numbers\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string132 = /.{0,1000}client\s\$ATTACKER\-IP:\$ATTACKER\-PORT\sR:\$PORT:socks.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string133 = /.{0,1000}cloudfail\.py\s\-\-target\sseo\.com\s\-\-tor.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string134 = /.{0,1000}cloudmapper\scollect\s\-\-account\sparent\s\-\-profile\sparent.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string135 = /.{0,1000}cloudmapper\sconfigure\sadd\-account\s\-\-config\-file\sconfig\.json\s\-\-name\sparent\s\-\-id\sXXX\s\-\-default\strue.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string136 = /.{0,1000}cloudmapper\sconfigure\sdiscover\-organization\-accounts.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string137 = /.{0,1000}cloudsplaining\screate\-multi\-account\-config\-file\s\-o\saccounts\.yml.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string138 = /.{0,1000}cloudsplaining\sdownload\s\-\-profile\ssomeprofile.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string139 = /.{0,1000}cloudsplaining\sscan\s\-\-input\-file\sdefault\.json.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string140 = /.{0,1000}cloudsplaining\sscan\-multi\-account\s\-c\saccounts\.yml\s\-r\sTargetRole\s\-\-output\-directory\s\.\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string141 = /.{0,1000}cloudsplaining\sscan\-policy\-file\s\-\-input\-file\sexamples\/policies\/wildcards\.json.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string142 = /.{0,1000}coercer\s\-d\s.{0,1000}\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string143 = /.{0,1000}corscanner\s\-i\surls\.txt\s\-t\s100.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string144 = /.{0,1000}cowpatty\s\-f\s.{0,1000}\.txt\s\-r\s.{0,1000}\.cap\s\-s\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string145 = /.{0,1000}cp\ssliver\-.{0,1000}\s\/opt\/tools\/bin.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string146 = /.{0,1000}crackhound\.py\s\-\-verbose\s\-\-password\s.{0,1000}\s\-\-plain\-text\s.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-file\s.{0,1000}\s\-\-add\-password\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string147 = /.{0,1000}crunch\s4\s7\sabcdefghijklmnopqrstuvwxyz1234567890\s\-o\swordlist\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string148 = /.{0,1000}curl\s.{0,1000}\s\-\-upload\-file\sbackdoor\.php\s\-v.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string149 = /.{0,1000}cypheroth\s\-u\sneo4j\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string150 = /.{0,1000}dacledit\.py\s\-action\swrite\s\-rights\sDCSync\s\-principal\s.{0,1000}\s\-target\-dn\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string151 = /.{0,1000}danielmiessler\/SecLists.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string152 = /.{0,1000}danielmiessler\/SecLists\.git.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string153 = /.{0,1000}darkarmour\s\-f\s.{0,1000}\.exe\s\-\-encrypt\sxor\s\-\-jmp\s\-\-loop\s7\s\-o\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string154 = /.{0,1000}das\sadd\s\-db\sdbname\smasscan\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string155 = /.{0,1000}das\sadd\s\-db\sdbname\srustscan\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string156 = /.{0,1000}das\sreport\s\-hosts\s192\.168\.1\.0\/24\s\-oA\sreport2.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string157 = /.{0,1000}das\sscan\s\-db\sdbname\s\-hosts\sall\s\-oA\sreport1\s\-nmap\s\'\-Pn\s\-sVC\s\-O\'\s\-parallel.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string158 = /.{0,1000}das\sscan\s\-db\sdbname\s\-ports\s22.{0,1000}80.{0,1000}443.{0,1000}445\s\-show.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string159 = /.{0,1000}dfscoerce\.py\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string160 = /.{0,1000}dirb\s.{0,1000}http.{0,1000}\s\/usr\/share\/seclists\/Discovery\/Web\-Content\/big\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string161 = /.{0,1000}dirkjanm\/ldapdomaindump.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string162 = /.{0,1000}dirkjanm\/PKINITtools.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string163 = /.{0,1000}dirsearch\s\-r\s\-w\s\/usr\/share\/wordlists\/seclists\/Discovery\/Web\-Content\/quickhits\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string164 = /.{0,1000}dnschef\s\-\-fakeip\s127\.0\.0\.1\s\-q.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string165 = /.{0,1000}dnsx\s\-silent\s\-d\s.{0,1000}\s\-w\sdns_worldlist\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string166 = /.{0,1000}dnsx\s\-silent\s\-d\sdomains\.txt\s\-w\sjira.{0,1000}grafana.{0,1000}jenkins.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string167 = /.{0,1000}DonPAPI\s\"\$DOMAIN\"\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string168 = /.{0,1000}droopescan\sscan\sdrupal\s\-u\s.{0,1000}\s\-t\s32.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string169 = /.{0,1000}drupwn\s\-\-mode\sexploit\s\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string170 = /.{0,1000}dump_WPA\-PBKDF2\-PMKID_EAPOL\.hashcat.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string171 = /.{0,1000}dump_WPA\-PMKID\-PBKDF2\.hashcat.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string172 = /.{0,1000}eaphammer\s\-i\seth0\s\-\-channel\s4\s\-\-auth\swpa\-eap\s\-\-essid\s.{0,1000}\s\-\-creds.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string173 = /.{0,1000}echo\s.{0,1000}\/24\s\|\sdnsx\s\-silent\s\-resp\-only\s\-ptr.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string174 = /.{0,1000}echo\s\'8\.8\.8\.8\'\s\|\shakrevdns.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string175 = /.{0,1000}EgeBalci\/amber\@latest.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string176 = /.{0,1000}enum4linux\-ng\s\-A\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string177 = /.{0,1000}evilmog\/ntlmv1\-multi.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string178 = /.{0,1000}evil\-winrm\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string179 = /.{0,1000}exegol4thewin.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string180 = /.{0,1000}ExegolController\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string181 = /.{0,1000}exegol\-docker\-build.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string182 = /.{0,1000}ExegolExceptions\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string183 = /.{0,1000}Exegol\-images\-main.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string184 = /.{0,1000}ExegolManager\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string185 = /.{0,1000}ExegolProgress\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string186 = /.{0,1000}ExegolPrompt\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string187 = /.{0,1000}eyewitness\s\-f\surls\.txt\s\-\-web.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string188 = /.{0,1000}faketime\s\'202.{0,1000}\szsh.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string189 = /.{0,1000}fcrackzip\s\-u\s\-v\s\-D\s\-p\s.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string190 = /.{0,1000}feroxbuster\s\-w\s.{0,1000}fzf\-wordlists.{0,1000}\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string191 = /.{0,1000}ffuf\s\-fs\s185\s\-c\s\-w\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string192 = /.{0,1000}fierce\s\-\-domain.{0,1000}\s\-\-dns\-servers\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string193 = /.{0,1000}finalrecon\.py\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string194 = /.{0,1000}findDelegation\.py\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string195 = /.{0,1000}FindUncommonShares\.p.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string196 = /.{0,1000}frida\s\-l\sdisableRoot\.js\s\-f\sowasp\.mstg\.uncrackable1.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string197 = /.{0,1000}frida\-ps\s\-U.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string198 = /.{0,1000}fuxploider\s\-\-url\s.{0,1000}\s\-\-not\-regex\s\"wrong\sfile\stype\".{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string199 = /.{0,1000}geowordlists\s\-\-postal\-code\s75001\s\-\-kilometers\s25\s\-\-output\-file\s\/tmp\/around_paris\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string200 = /.{0,1000}Get\-GPPPassword\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string201 = /.{0,1000}GetNPUsers\.py\s\-request.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string202 = /.{0,1000}getnthash\.py\s\-key\s\'8eb7a6388780dd52eb358769dc53ff685fd135f89c4ef55abb277d7d98995f72\'.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string203 = /.{0,1000}getST\.py\s\-k\s\-no\-pass\s\-spn.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string204 = /.{0,1000}getTGT\.py\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string205 = /.{0,1000}gettgtpkinit\.py\s\-cert\-pfx.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string206 = /.{0,1000}gettgtpkinit\.py\s\-pfx\-base64\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string207 = /.{0,1000}gMSADumper\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string208 = /.{0,1000}gobuster\sdir\s\-w\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string209 = /.{0,1000}goldencopy\s.{0,1000}\s\-\-password\s.{0,1000}\s\-\-stealth\s\-\-krbtgt\s060ee2d06c5648e60a9ed916c9221ad19d90e5fb7b1cccf9d51f540fe991ada1\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string210 = /.{0,1000}gopherus\s\-\-exploit\smysql.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string211 = /.{0,1000}gosecretsdump\s\-ntds\s.{0,1000}\-system\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string212 = /.{0,1000}goshs\s\-b\s.{0,1000}\s\-\-ssl\s\-\-self\-signed\s\-p\s.{0,1000}\s\-d\s\/workspace.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string213 = /.{0,1000}gpp\-decrypt\.py\s\-f\sgroups\.xml.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string214 = /.{0,1000}h2csmuggler\s\-\-scan\-list\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string215 = /.{0,1000}h2csmuggler\s\-x\s.{0,1000}\s\-\-test.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string216 = /.{0,1000}h8mail\s\-t\s.{0,1000}\@.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string217 = /.{0,1000}Hackndo\/sprayhound.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string218 = /.{0,1000}Hackplayers\/evil\-winrm.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string219 = /.{0,1000}hackrf_sweep\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string220 = /.{0,1000}hashonymize\s\-\-ntds\s.{0,1000}\s\-\-kerberoast\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string221 = /.{0,1000}HashPals\/Name\-That\-Hash.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string222 = /.{0,1000}\-\-hash\-type\s1000\s\-\-potfile\-path.{0,1000}\.ntds\.cracked.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string223 = /.{0,1000}hcxdumptool\s\-i\swlan1\s\-o\s.{0,1000}\s\-\-active_beacon\s\-\-enable_status\=1.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string224 = /.{0,1000}hcxhashtool\s\-i\s.{0,1000}\.hashcat\s\-\-info\sstdout.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string225 = /.{0,1000}hcxpcapngtool\s\-\-all\s\-o\s.{0,1000}\.hashcat.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string226 = /.{0,1000}hcxpcapngtool\s\-o\s.{0,1000}\.hashcat\s.{0,1000}\.pcapng.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string227 = /.{0,1000}HOST\/EXEGOL\-01\..{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string228 = /.{0,1000}Host:\sFUZZ\.machine\.org.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string229 = /.{0,1000}http.{0,1000}\s\|\shakrawler\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string230 = /.{0,1000}HTTP\/EXEGOL\-01\..{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string231 = /.{0,1000}infoga\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string232 = /.{0,1000}install_aclpwn.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string233 = /.{0,1000}install_ad_apt_tools.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string234 = /.{0,1000}install_adidnsdump.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string235 = /.{0,1000}install_amber.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string236 = /.{0,1000}install_bloodhound.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string237 = /.{0,1000}install_bloodhound\-import.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string238 = /.{0,1000}install_bloodhound\-py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string239 = /.{0,1000}install_bloodhound\-quickwin.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string240 = /.{0,1000}install_certipy.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string241 = /.{0,1000}install_certsync.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string242 = /.{0,1000}install_coercer.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string243 = /.{0,1000}install_crackhound.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string244 = /.{0,1000}install_cracking_apt_tools.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string245 = /.{0,1000}install_crackmapexec.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string246 = /.{0,1000}install_cypheroth.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string247 = /.{0,1000}install_darkarmour.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string248 = /.{0,1000}install_dfscoerce.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string249 = /.{0,1000}install_donpapi.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string250 = /.{0,1000}install_enum4linux\-ng.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string251 = /.{0,1000}install_enyx.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string252 = /.{0,1000}install_evilwinrm.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string253 = /.{0,1000}install_finduncommonshares.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string254 = /.{0,1000}install_gmsadumper.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string255 = /.{0,1000}install_goldencopy.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string256 = /.{0,1000}install_gosecretsdump.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string257 = /.{0,1000}install_gpp\-decrypt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string258 = /.{0,1000}install_hashonymize.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string259 = /.{0,1000}install_impacket.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string260 = /.{0,1000}install_keepwn.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string261 = /.{0,1000}install_kerbrute.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string262 = /.{0,1000}install_krbrelayx.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string263 = /.{0,1000}install_ldapdomaindump.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string264 = /.{0,1000}install_ldaprelayscan.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string265 = /.{0,1000}install_ldapsearch\-ad.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string266 = /.{0,1000}install_lnkup.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string267 = /.{0,1000}install_lsassy.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string268 = /.{0,1000}install_manspider.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string269 = /.{0,1000}install_mitm6_pip.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string270 = /.{0,1000}install_noPac.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string271 = /.{0,1000}install_ntlmv1\-multi.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string272 = /.{0,1000}install_oaburl.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string273 = /.{0,1000}install_PassTheCert.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string274 = /.{0,1000}install_pcredz.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string275 = /.{0,1000}install_petitpotam.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string276 = /.{0,1000}install_pkinittools.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string277 = /.{0,1000}install_polenum.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string278 = /.{0,1000}install_privexchange.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string279 = /.{0,1000}install_pth\-tools.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string280 = /.{0,1000}install_pygpoabuse.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string281 = /.{0,1000}install_pykek.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string282 = /.{0,1000}install_pylaps.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string283 = /.{0,1000}install_pypykatz.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string284 = /.{0,1000}install_pywhisker.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string285 = /.{0,1000}install_pywsus.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string286 = /.{0,1000}install_responder.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string287 = /.{0,1000}install_roastinthemiddle.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string288 = /.{0,1000}install_ruler.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string289 = /.{0,1000}install_rusthound.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string290 = /.{0,1000}install_shadowcoerce.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string291 = /.{0,1000}install_smartbrute.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string292 = /.{0,1000}install_smbmap.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string293 = /.{0,1000}install_smtp\-user\-enum.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string294 = /.{0,1000}install_sprayhound.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string295 = /.{0,1000}install_targetedKerberoast.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string296 = /.{0,1000}install_webclientservicescanner.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string297 = /.{0,1000}install_windapsearch\-go.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string298 = /.{0,1000}install_zerologon.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string299 = /.{0,1000}\-\-interface\s.{0,1000}\s\-\-wpad\s\-\-lm\s\-\-disable\-ess.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string300 = /.{0,1000}ip\slink\sset\sligolo\sup.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string301 = /.{0,1000}ip\sroute\sadd\s.{0,1000}\sdev\sligolo.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string302 = /.{0,1000}ip\stuntap\sadd\suser\sroot\smode\stun\sligolo.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string303 = /.{0,1000}irkjanm\/krbrelayx.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string304 = /.{0,1000}jackit\s\-\-reset\s\-\-debug.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string305 = /.{0,1000}jdwp\-shellifier\.py\s\-t\s.{0,1000}\s\-p\s.{0,1000}\s\-\-cmd\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string306 = /.{0,1000}john\s\-\-format\=.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string307 = /.{0,1000}john\s\-\-wordlist\=.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string308 = /.{0,1000}joomscan\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string309 = /.{0,1000}JuicyPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string310 = /.{0,1000}\-K\slsass_loot.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string311 = /.{0,1000}KeePwn\splugin\sadd\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-d\s.{0,1000}\s\-t\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string312 = /.{0,1000}KeePwn\splugin\scheck\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string313 = /.{0,1000}kerbrute\sbruteuser\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string314 = /.{0,1000}kerbrute\spasswordspray\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string315 = /.{0,1000}kerbrute\suserenum\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string316 = /.{0,1000}kraken\.py\s\-\-connect\s\-\-mode\s.{0,1000}\s\-\-profile\s.{0,1000}\s\-\-compiler\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string317 = /.{0,1000}KRB5CCNAME\=.{0,1000}\.ccache.{0,1000}\sgetST\.py\s\-self\s\-impersonate\s.{0,1000}\s\-k\s\-no\-pass\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string318 = /.{0,1000}krbrelayx\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string319 = /.{0,1000}LdapRelayScan\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string320 = /.{0,1000}libnfc_crypto1_crack\sa0a1a2a3a4a5\s0\sA\s4\sB.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string321 = /.{0,1000}ligolo\-ng\s\-selfcert.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string322 = /.{0,1000}linkedin2username\.py\s\-u.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string323 = /.{0,1000}linpeas_darwin_amd64.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string324 = /.{0,1000}linpeas_darwin_arm64.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string325 = /.{0,1000}linpeas_linux_386.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string326 = /.{0,1000}linpeas_linux_amd64.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string327 = /.{0,1000}linpeas_linux_arm.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string328 = /.{0,1000}linux\-exploit\-suggester\.sh.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string329 = /.{0,1000}linux\-smart\-enumeration\.sh.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string330 = /.{0,1000}lnk\-generate\.py\s\-\-host\s.{0,1000}\s\-\-type\sntlm\s\-\-output\s.{0,1000}\.lnk.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string331 = /.{0,1000}lookupsid\.py\s\-hashes\s:.{0,1000}\s.{0,1000}\@.{0,1000}\s0.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string332 = /.{0,1000}lsassy\s\-v\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string333 = /.{0,1000}manspider\s\-\-threads\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-H\s.{0,1000}\s\-\-content\sadmin.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string334 = /.{0,1000}mitm6\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string335 = /.{0,1000}ms14\-068\.py\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string336 = /.{0,1000}ms14\-068\.py\s\-u.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string337 = /.{0,1000}noPac\s.{0,1000}\s\-dc\-ip\s.{0,1000}\s\-\-impersonate\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string338 = /.{0,1000}nrf24\-scanner\.py\s\-l\s\-v.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string339 = /.{0,1000}nth\s\-\-text\s5f4dcc3b5aa765d61d8327deb882cf99.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string340 = /.{0,1000}ntlmrelayx\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string341 = /.{0,1000}ntlmv1\-multi\s\-\-ntlmv1\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string342 = /.{0,1000}nuclei\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string343 = /.{0,1000}oaburl\.py\s.{0,1000}\/.{0,1000}:.{0,1000}\@.{0,1000}\s\-e\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string344 = /.{0,1000}onesixtyone\s\-c\s.{0,1000}snmp_default_pass\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string345 = /.{0,1000}onesixtyone\s\-c\s.{0,1000}wordlists\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string346 = /.{0,1000}pass\-station\ssearch\stomcat.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string347 = /.{0,1000}passthecert\.py\s\-action\sadd_computer\s\-crt\suser\.crt\s\-key\suser\.key\s\-domain\s.{0,1000}\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string348 = /.{0,1000}patator\sftp_login\shost\=.{0,1000}\suser\=FILE0\s0\=.{0,1000}\.txt\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string349 = /.{0,1000}PCredz\s\-f\s.{0,1000}\.pcap.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string350 = /.{0,1000}pdfcrack\s\-f\s.{0,1000}\.pdf.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string351 = /.{0,1000}petitpotam\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string352 = /.{0,1000}phoneinfoga\sscan\s\-n\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string353 = /.{0,1000}photon\.py\s\-u\s.{0,1000}\s\-l\s3\s\-t\s100\s\-\-wayback.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string354 = /.{0,1000}php_filter_chain_generator\s\-\-chain\s.{0,1000}php\ssystem.{0,1000}\'cmd\'\].{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string355 = /.{0,1000}phpggc\s\-l.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string356 = /.{0,1000}phpggc\smonolog\/rce1\sassert\s\'phpinfo\(\)\'.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string357 = /.{0,1000}phpggc\ssymfony\/rce1\sid.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string358 = /.{0,1000}pip\sinstall\sexegol.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string359 = /.{0,1000}pm3\s\-p\s\/dev\/ttyACM0.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string360 = /.{0,1000}pre2k\sauth\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string361 = /.{0,1000}printerbug\.py\s.{0,1000}:.{0,1000}\@.{0,1000}\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string362 = /.{0,1000}privexchange\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string363 = /.{0,1000}prowler\sgcp\s\-\-credentials\-file\spath.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string364 = /.{0,1000}proxmark3\s\-p\s\/dev\/ttyACM0.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string365 = /.{0,1000}proxychains\satexec\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string366 = /.{0,1000}proxychains\sdcomexec\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string367 = /.{0,1000}proxychains\spsexec\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string368 = /.{0,1000}proxychains\ssecretsdump.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string369 = /.{0,1000}proxychains\ssmbexec\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string370 = /.{0,1000}proxychains\swmiexec\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string371 = /.{0,1000}pth\-net\srpc\sgroup\smembers\s.{0,1000}Domain\sadmins.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string372 = /.{0,1000}pth\-net\srpc\sgroup\smembers\s.{0,1000}Exchange\sServers.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string373 = /.{0,1000}pth\-net\srpc\spassword\s.{0,1000}\s\-U\s.{0,1000}\s\-S\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string374 = /.{0,1000}pth\-net\srpc\suser\sadd\s.{0,1000}\s\-U\s.{0,1000}\-S\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string375 = /.{0,1000}pwncat\-cs\s.{0,1000}:.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string376 = /.{0,1000}pwncat\-cs\s\-lp\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string377 = /.{0,1000}pwncat\-cs\sssh:\/\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string378 = /.{0,1000}pwndb\s\-\-target\s\@.{0,1000}\s\-\-output\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string379 = /.{0,1000}pygpoabuse\s.{0,1000}\s\-hashes\slm:.{0,1000}\s\-gpo\-id\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string380 = /.{0,1000}pyLAPS\.py\s\-\-action\sget\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string381 = /.{0,1000}pyrit\s\-e\s.{0,1000}\screate_essid.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string382 = /.{0,1000}pyrit\s\-i\s.{0,1000}\.txt\simport_passwords.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string383 = /.{0,1000}pyrit\s\-r\s.{0,1000}\.pcap\sattack_db.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string384 = /.{0,1000}pyrit\s\-r\s.{0,1000}\.pcap\s\-b\s.{0,1000}\s\-i\s.{0,1000}\.txt\sattack_passthrough.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string385 = /.{0,1000}python\srsf\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string386 = /.{0,1000}python3\srsf\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string387 = /.{0,1000}pywhisker\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string388 = /.{0,1000}rbcd\.py\s\-delegate\-from\s.{0,1000}\s\-delegate\-to\s.{0,1000}\s\-dc\-ip\s.{0,1000}\s\-action\swrite\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string389 = /.{0,1000}rebootuser\/LinEnum.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string390 = /.{0,1000}reg\.py\s.{0,1000}\@.{0,1000}\ssave\s\-keyName\s\'HKLM\\SAM.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string391 = /.{0,1000}reg\.py\s.{0,1000}\@.{0,1000}\ssave\s\-keyName\s\'HKLM\\SECURITY.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string392 = /.{0,1000}reg\.py\s.{0,1000}\@.{0,1000}\ssave\s\-keyName\s\'HKLM\\SYSTEM.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string393 = /.{0,1000}register\-python\-argcomplete\s\-\-no\-defaults\sexegol.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string394 = /.{0,1000}renameMachine\.py\s\-current\-name\s.{0,1000}\s\-new\-name\s.{0,1000}\s\-dc\-ip\s.{0,1000}\s.{0,1000}:.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string395 = /.{0,1000}responder\s\-\-interface.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string396 = /.{0,1000}Responder\/tools\/MultiRelay\/bin\/Runas\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string397 = /.{0,1000}Responder\/tools\/MultiRelay\/bin\/Syssvc\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string398 = /.{0,1000}responder\-http\-off.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string399 = /.{0,1000}responder\-http\-on.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string400 = /.{0,1000}responder\-smb\-off.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string401 = /.{0,1000}responder\-smb\-on.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string402 = /.{0,1000}rlwrap\snc\s\-lvnp\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string403 = /.{0,1000}roastinthemiddle\s\-i\s.{0,1000}\s\-t\s.{0,1000}\s\-u\s.{0,1000}\.txt\s\-g\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string404 = /.{0,1000}ropnop\/go\-windapsearch.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string405 = /.{0,1000}rsactftool\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string406 = /.{0,1000}rsactftool.{0,1000}\s\-\-dumpkey\s\-\-key\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string407 = /.{0,1000}ruler\s.{0,1000}\sabk\sdump\s\-o\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string408 = /.{0,1000}ruler\s\-k\s\-d\s.{0,1000}\sbrute\s\-\-users\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string409 = /.{0,1000}rusthound\s.{0,1000}\s\-\-zip\s\-\-ldaps\s\-\-adcs\s\-\-old\-bloodhound.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string410 = /.{0,1000}samdump2\sSYSTEM\sSAM\s\>\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string411 = /.{0,1000}\-\-script\sbroadcast\-dhcp\-discover.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string412 = /.{0,1000}searchsploit\s\-m\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string413 = /.{0,1000}searchsploit\s\-x\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string414 = /.{0,1000}secret_fragment_exploit\.py\s.{0,1000}\/_fragment.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string415 = /.{0,1000}secretsdump\s\-sam\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string416 = /.{0,1000}shadowcoerce\.py\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string417 = /.{0,1000}ShawnDEvans\/smbmap.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string418 = /.{0,1000}shellerator\s\-\-reverse\-shell\s\-\-lhost\s.{0,1000}\s\-\-lport\s.{0,1000}\s\-\-type\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string419 = /.{0,1000}ShutdownRepo\/smartbrute.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string420 = /.{0,1000}sipvicious_svcrack.{0,1000}\s\-u100/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string421 = /.{0,1000}smartbrute\s.{0,1000}kerberos.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string422 = /.{0,1000}\-smb2support\s\-\-remove\-mic\s\-\-shadow\-credentials\s\-\-shadow\-target\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string423 = /.{0,1000}smbexec\.py\s\-hashes\s:.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string424 = /.{0,1000}smbexec\.py\s\-share.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string425 = /.{0,1000}smbmap\s\-u\sguest\s\-H\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string426 = /.{0,1000}smbpasswd\.py\s\-newpass\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string427 = /.{0,1000}smbserver\.py\s\-smb2support\sEXEGOL.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string428 = /.{0,1000}smtp\-user\-enum\s.{0,1000}\s\-M\sEXPN\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string429 = /.{0,1000}smtp\-user\-enum\s.{0,1000}\s\-M\sRCPT\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string430 = /.{0,1000}smtp\-user\-enum\s.{0,1000}\s\-M\sVRFY\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string431 = /.{0,1000}spiderfoot\s\-l\s127\.0\.0\.1:.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string432 = /.{0,1000}spiderfoot\-cli\s\-s\shttp.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string433 = /.{0,1000}SpoolSample_v4\.5_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string434 = /.{0,1000}sprayhound\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string435 = /.{0,1000}sqlmap\s\-\-forms\s\-\-batch\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string436 = /.{0,1000}sshuttle\s\-r\s.{0,1000}0\.0\.0\.0\/24.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string437 = /.{0,1000}ssrfmap\s\-r\s.{0,1000}\.txt\s\-p\sid\s\-m\sreadfiles.{0,1000}portscan.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string438 = /.{0,1000}subfinder\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string439 = /.{0,1000}subfinder\s\-silent\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string440 = /.{0,1000}sublist3r\s\-v\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string441 = /.{0,1000}swaks\s\-\-to\s.{0,1000}\s\-\-from\s.{0,1000}\s\-\-header\s.{0,1000}Subject:\s.{0,1000}\s\-\-body\s.{0,1000}\s\-\-server\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string442 = /.{0,1000}swisskyrepo\/SSRFmap.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string443 = /.{0,1000}tarunkant\/Gopherus.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string444 = /.{0,1000}ThePorgs\/Exegol\-images.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string445 = /.{0,1000}ticketer\.py\s\-nthash.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string446 = /.{0,1000}timing_attack\s.{0,1000}\s\-\-brute\-force.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string447 = /.{0,1000}tls\-scanner\s\-connect\s.{0,1000}:.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string448 = /.{0,1000}tomcatWarDeployer\s\-v\s\-x\s\-p\s.{0,1000}\s\-H\s.{0,1000}\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string449 = /.{0,1000}trevorspray\s.{0,1000}\-\-recon\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string450 = /.{0,1000}trevorspray\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string451 = /.{0,1000}trickster0\/Enyx.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string452 = /.{0,1000}twint\s\-g\=.{0,1000}km.{0,1000}\s\-o\s.{0,1000}\s\-\-csv.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string453 = /.{0,1000}twint\s\-u\s.{0,1000}\s\-\-since\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string454 = /.{0,1000}uberfile\s\-\-lhost.{0,1000}\s\-\-lport\s.{0,1000}\s\-\-target\-os\s.{0,1000}\s\-\-downloader\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string455 = /.{0,1000}wafw00f\shttps:\/\/.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string456 = /.{0,1000}webclientservicescanner\s\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string457 = /.{0,1000}webshell\-exegol\.php.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string458 = /.{0,1000}weevely\sgenerate\s.{0,1000}\.php.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string459 = /.{0,1000}weevely\shttps:\/\/.{0,1000}\.php\s.{0,1000}\sid.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string460 = /.{0,1000}wfuzz\s\-\-.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string461 = /.{0,1000}Wh1t3Fox\/polenum.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string462 = /.{0,1000}wifite\s\-\-dict\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string463 = /.{0,1000}wifite\s\-\-kill.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string464 = /.{0,1000}windapsearch\s\-\-dc\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string465 = /.{0,1000}winPEAS\.bat.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string466 = /.{0,1000}winPEASany\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string467 = /.{0,1000}winPEASany_ofs\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string468 = /.{0,1000}winPEASx64\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string469 = /.{0,1000}winPEASx86\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string470 = /.{0,1000}winPEASx86_ofs\.exe.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string471 = /.{0,1000}wmiexec\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string472 = /.{0,1000}wpscan\s\-\-api\-token\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string473 = /.{0,1000}XSpear\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string474 = /.{0,1000}xsrfprobe\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string475 = /.{0,1000}xsser\s\-u\s.{0,1000}\s\-g\s.{0,1000}\/login\?password\=.{0,1000}\s\-\-Coo.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string476 = /.{0,1000}zerologon\sclone\s.{0,1000}https.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string477 = /.{0,1000}zerologon\-restore\s.{0,1000}\s\-target\-ip\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
