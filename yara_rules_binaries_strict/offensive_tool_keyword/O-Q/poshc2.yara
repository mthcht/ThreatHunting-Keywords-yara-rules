rule poshc2
{
    meta:
        description = "Detection patterns for the tool 'poshc2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "poshc2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string1 = /\s\-c2server\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string2 = /\s\-daisyserver\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string3 = /\s\-LocalPoshC2ProjectDir\s/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and Lateral Movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string4 = /\s\-LocalPoshC2ProjectDir\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string5 = /\s\-Payload\s.{0,100}\s\-method\ssysprep/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string6 = /\sPayloadsDirectory/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string7 = /\sPoshC2\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string8 = /\s\-PoshC2Dir\s/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and Lateral Movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string9 = /\s\-PoshC2Dir\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string10 = /\sSharpSocks\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string11 = /\/bin\/posh/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string12 = /\/C2Server\.py/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string13 = /\/Macro\-Payloads\.py/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string14 = /\/nettitude\// nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string15 = /\/opt\/PoshC2/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string16 = /\/posh\.key/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and Lateral Movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string17 = /\/PoshC2/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string18 = /\/poshc2\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string19 = /\/PoshC2\// nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string20 = /\/posh\-config/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string21 = /\/posh\-log/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string22 = /\/posh\-project/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string23 = /\/posh\-server/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string24 = /\/posh\-service/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string25 = /\/posh\-stop\-service/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string26 = /\/posh\-update/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string27 = /\/SharpHandler\.py/ nocase ascii wide
        // Description: pipe name from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string28 = /\\jaccdpqnvbrrxlaf/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string29 = /\\PoshC2/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string30 = /_posh\-common/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string31 = /_Shellcode\.bin/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string32 = /brute\-locadmin\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string33 = /bypass\-amsi/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string34 = /C2\.KillDate/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string35 = /C2\.UserAgent/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string36 = /clipboard\-monitor\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string37 = /createdaisypayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string38 = /createlinuxpayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string39 = /createnewpayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string40 = /createnewshellcode/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string41 = /createpbindpayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string42 = /createproxypayload\s\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string43 = /createproxypayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string44 = /cred\-popper\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string45 = /dcomexec\s\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string46 = /dllsearcher\s.{0,100}\.dll/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string47 = /find\-allvulns/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string48 = /find\-interestingfile\s\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string49 = /fpc\s\-c\sSeatbelt/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string50 = /get_c2_messages/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string51 = /get_c2server_all/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string52 = /get_cmd_from_task_id/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string53 = /get_implants_all/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string54 = /get_newimplanturl/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string55 = /get_sharpurls/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string56 = /get\-creditcarddata\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string57 = /getdllbaseaddress/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string58 = /get\-dodgyprocesses/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string59 = /getgppgroups\s\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string60 = /getgpppassword\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string61 = /get\-implantworkingdirectory/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string62 = /Get\-KeystrokeData/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string63 = /get\-keystrokes/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string64 = /get\-killdate/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string65 = /get\-netfileserver\s\-domain\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string66 = /get\-passnotexp/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string67 = /get\-process\s.{0,100}amsi\.dll/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string68 = /getremoteprocesslisting/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string69 = /get\-screenshot/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string70 = /get\-screenshotallwindows/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string71 = /get\-wmiregcachedrdpconnection/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string72 = /get\-wmireglastloggedon/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string73 = /get\-wmiregmounteddrive/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string74 = /hide\-implant/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string75 = /inject\-shellcode\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string76 = /installexe\-persistence/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string77 = /install\-persistence/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string78 = /install\-persistence\-cron/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string79 = /invoke\-aclscanner/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string80 = /invoke\-arpscan/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string81 = /invoke\-bloodhound/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string82 = /invoke\-daisychain/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string83 = /invoke\-dcompayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string84 = /invoke\-edrchecker/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string85 = /invoke\-eternalblue/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string86 = /invoke\-hostenum\s\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string87 = /invoke\-hostscan/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string88 = /invoke\-kerberoast\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string89 = /Invoke\-Pbind\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string90 = /Invoke\-Pbind\.ps1/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string91 = /invoke\-pipekat\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string92 = /invoke\-psexecpayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string93 = /Invoke\-PsUACme/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string94 = /invoke\-runaspayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string95 = /invoke\-sharefinder\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string96 = /invoke\-smbclient\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string97 = /invoke\-smbexec\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string98 = /invoke\-smblogin\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string99 = /invoke\-sniffer\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string100 = /invoke\-urlcheck\s\-urls/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string101 = /invoke\-winrmsession/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string102 = /invoke\-wmiexec\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string103 = /invoke\-wmijspayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string104 = /invoke\-wmipayload/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string105 = /kill\-implant/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string106 = /label\-implant\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string107 = /ldap\-searcher\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string108 = /linuxprivchecker/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string109 = /loadmodule\s.{0,100}\.ps1/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string110 = /loadmodume\s.{0,100}\/modules\/.{0,100}\.ps1.{0,100}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string111 = /lockless\s.{0,100}\.dat/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string112 = /PayloadCommsHost/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string113 = /Posh_v4_dropper_/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string114 = /Posh_v4_x64_.{0,100}\.bin/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string115 = /Posh_v4_x86_.{0,100}\.bin/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string116 = /PoshC2\-.{0,100}\.zip/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string117 = /poshc2\.server/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string118 = /poshc2\.service/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and Lateral Movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string119 = /poshc2\-ansible\-main\.yml/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string120 = /posh\-cookie\-decryptor/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string121 = /posh\-delete\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string122 = /posh\-project\s/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and Lateral Movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string123 = /posh\-project\s\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string124 = /posh\-server\s\-/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and Lateral Movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string125 = /posh\-server\s\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string126 = /posh\-update\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string127 = /process_mimikatz/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string128 = /pslo\s.{0,100}\.ps1/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string129 = /removeexe\-persistence/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string130 = /remove\-persistence/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string131 = /remove\-persistence\-cron/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string132 = /runas\-netonly\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string133 = /run\-dll\sSharpSploit/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string134 = /safetydump/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string135 = /seatbelt\s\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string136 = /seatbelt\sall/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string137 = /set\-killdate\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string138 = /set\-pushover\-applicationtoken/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string139 = /set\-pushover\-userkeys/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string140 = /shadowcopy\senum/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string141 = /Sharp_v4_x64.{0,100}\.bin/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string142 = /Sharp_v4_x86.{0,100}\.bin/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string143 = /sharpapplocker/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string144 = /sharpchromium\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string145 = /sharpcookiemonster/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string146 = /sharpedrchecker/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string147 = /sharphound\s\-/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string148 = /sharpps\s\$psversiontable/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string149 = /sharpps\sget\-process/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string150 = /sharpsc\s.{0,100}cmd/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string151 = /sharptelnet\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string152 = /sharpweb\sall/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string153 = /sharpwmi\saction\=/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string154 = /standin\s\-\-asrep/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string155 = /standin\s\-\-dc/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string156 = /standin\s\-\-delegation/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string157 = /standin\s\-\-group\s.{0,100}Domain\sAdmins/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string158 = /standin\s\-\-object\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string159 = /standin\s\-\-spn/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string160 = /startanotherimplant/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string161 = /startdaisy/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string162 = /start\-keystrokes/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string163 = /start\-keystrokes\-writefile/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string164 = /start\-process\sntdsutil\.exe\s.{0,100}create\sfull.{0,100}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string165 = /stopdaisy/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string166 = /stop\-keystrokes/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string167 = /sweetpotato\s\-p/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string168 = /temp\\pbind\.exe/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string169 = /timestomp\sc\:/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string170 = /unhide\-implant/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string171 = /XOR\-Payloads\.py/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string172 = /posh\s\-u\s/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string173 = /runof\s.{0,100}\.o/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and Lateral Movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string174 = /runpe\s.{0,100}\.exe/ nocase ascii wide
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
