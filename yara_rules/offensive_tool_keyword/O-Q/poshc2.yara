rule poshc2
{
    meta:
        description = "Detection patterns for the tool 'poshc2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "poshc2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string1 = /.{0,1000}\s\-c2server\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string2 = /.{0,1000}\s\-daisyserver\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string3 = /.{0,1000}\s\-LocalPoshC2ProjectDir\s.{0,1000}/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and lateral movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string4 = /.{0,1000}\s\-LocalPoshC2ProjectDir\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string5 = /.{0,1000}\s\-Payload\s.{0,1000}\s\-method\ssysprep.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string6 = /.{0,1000}\sPayloadsDirectory.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string7 = /.{0,1000}\sPoshC2\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string8 = /.{0,1000}\s\-PoshC2Dir\s.{0,1000}/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and lateral movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string9 = /.{0,1000}\s\-PoshC2Dir\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string10 = /.{0,1000}\sSharpSocks\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string11 = /.{0,1000}\/bin\/posh.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string12 = /.{0,1000}\/C2Server\.py.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string13 = /.{0,1000}\/Macro\-Payloads\.py.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string14 = /.{0,1000}\/nettitude\/.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string15 = /.{0,1000}\/opt\/PoshC2.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string16 = /.{0,1000}\/posh\.key.{0,1000}/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and lateral movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string17 = /.{0,1000}\/PoshC2.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string18 = /.{0,1000}\/poshc2\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string19 = /.{0,1000}\/PoshC2\/.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string20 = /.{0,1000}\/posh\-config.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string21 = /.{0,1000}\/posh\-log.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string22 = /.{0,1000}\/posh\-project.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string23 = /.{0,1000}\/posh\-server.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string24 = /.{0,1000}\/posh\-service.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string25 = /.{0,1000}\/posh\-stop\-service.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string26 = /.{0,1000}\/posh\-update.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string27 = /.{0,1000}\/SharpHandler\.py.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string28 = /.{0,1000}\\PoshC2.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string29 = /.{0,1000}_posh\-common.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string30 = /.{0,1000}_Shellcode\.bin.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string31 = /.{0,1000}brute\-locadmin\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string32 = /.{0,1000}bypass\-amsi.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string33 = /.{0,1000}C2\.KillDate.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string34 = /.{0,1000}C2\.UserAgent.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string35 = /.{0,1000}clipboard\-monitor\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string36 = /.{0,1000}createdaisypayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string37 = /.{0,1000}createlinuxpayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string38 = /.{0,1000}createnewpayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string39 = /.{0,1000}createnewshellcode.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string40 = /.{0,1000}createpbindpayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string41 = /.{0,1000}createproxypayload\s\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string42 = /.{0,1000}createproxypayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string43 = /.{0,1000}cred\-popper\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string44 = /.{0,1000}dcomexec\s\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string45 = /.{0,1000}dllsearcher\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string46 = /.{0,1000}find\-allvulns.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string47 = /.{0,1000}find\-interestingfile\s\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string48 = /.{0,1000}fpc\s\-c\sSeatbelt.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string49 = /.{0,1000}get_c2_messages.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string50 = /.{0,1000}get_c2server_all.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string51 = /.{0,1000}get_cmd_from_task_id.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string52 = /.{0,1000}get_implants_all.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string53 = /.{0,1000}get_newimplanturl.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string54 = /.{0,1000}get_sharpurls.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string55 = /.{0,1000}get\-creditcarddata\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string56 = /.{0,1000}getdllbaseaddress.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string57 = /.{0,1000}get\-dodgyprocesses.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string58 = /.{0,1000}getgppgroups\s\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string59 = /.{0,1000}getgpppassword\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string60 = /.{0,1000}get\-implantworkingdirectory.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string61 = /.{0,1000}Get\-KeystrokeData.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string62 = /.{0,1000}get\-keystrokes.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string63 = /.{0,1000}get\-killdate.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string64 = /.{0,1000}get\-netfileserver\s\-domain\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string65 = /.{0,1000}get\-passnotexp.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string66 = /.{0,1000}get\-process\s.{0,1000}amsi\.dll.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string67 = /.{0,1000}getremoteprocesslisting.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string68 = /.{0,1000}get\-screenshot.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string69 = /.{0,1000}get\-screenshotallwindows.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string70 = /.{0,1000}get\-wmiregcachedrdpconnection.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string71 = /.{0,1000}get\-wmireglastloggedon.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string72 = /.{0,1000}get\-wmiregmounteddrive.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string73 = /.{0,1000}hide\-implant.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string74 = /.{0,1000}inject\-shellcode\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string75 = /.{0,1000}installexe\-persistence.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string76 = /.{0,1000}install\-persistence.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string77 = /.{0,1000}install\-persistence\-cron.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string78 = /.{0,1000}invoke\-aclscanner.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string79 = /.{0,1000}invoke\-arpscan.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string80 = /.{0,1000}invoke\-bloodhound.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string81 = /.{0,1000}invoke\-daisychain.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string82 = /.{0,1000}invoke\-dcompayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string83 = /.{0,1000}invoke\-edrchecker.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string84 = /.{0,1000}invoke\-eternalblue.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string85 = /.{0,1000}invoke\-hostenum\s\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string86 = /.{0,1000}invoke\-hostscan.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string87 = /.{0,1000}invoke\-kerberoast\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string88 = /.{0,1000}invoke\-pipekat\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string89 = /.{0,1000}invoke\-psexecpayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string90 = /.{0,1000}Invoke\-PsUACme.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string91 = /.{0,1000}invoke\-runaspayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string92 = /.{0,1000}invoke\-sharefinder\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string93 = /.{0,1000}invoke\-smbclient\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string94 = /.{0,1000}invoke\-smbexec\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string95 = /.{0,1000}invoke\-smblogin\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string96 = /.{0,1000}invoke\-sniffer\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string97 = /.{0,1000}invoke\-urlcheck\s\-urls.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string98 = /.{0,1000}invoke\-winrmsession.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string99 = /.{0,1000}invoke\-wmiexec\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string100 = /.{0,1000}invoke\-wmijspayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string101 = /.{0,1000}invoke\-wmipayload.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string102 = /.{0,1000}kill\-implant.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string103 = /.{0,1000}label\-implant\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string104 = /.{0,1000}ldap\-searcher\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string105 = /.{0,1000}linuxprivchecker.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string106 = /.{0,1000}loadmodule\s.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string107 = /.{0,1000}loadmodume\s.{0,1000}\/modules\/.{0,1000}\.ps1.{0,1000}.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string108 = /.{0,1000}lockless\s.{0,1000}\.dat.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string109 = /.{0,1000}PayloadCommsHost.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string110 = /.{0,1000}Posh_v4_dropper_.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string111 = /.{0,1000}Posh_v4_x64_.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string112 = /.{0,1000}Posh_v4_x86_.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string113 = /.{0,1000}PoshC2\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string114 = /.{0,1000}poshc2\.server.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string115 = /.{0,1000}poshc2\.service.{0,1000}/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and lateral movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string116 = /.{0,1000}poshc2\-ansible\-main\.yml.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string117 = /.{0,1000}posh\-cookie\-decryptor.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string118 = /.{0,1000}posh\-delete\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string119 = /.{0,1000}posh\-project\s.{0,1000}/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and lateral movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string120 = /.{0,1000}posh\-project\s\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string121 = /.{0,1000}posh\-server\s\-.{0,1000}/ nocase ascii wide
        // Description: PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming. post-exploitation and lateral movement. PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools. allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python implants with payloads written in PowerShell v2 and v4. C++ and C# source code. a variety of executables. DLLs and raw shellcode in addition to a Python2 payload. These enable C2 functionality on a wide range of devices and operating systems. including Windows. *nix and OSX.
        // Reference: https://github.com/nettitude/PoshC2
        $string122 = /.{0,1000}posh\-server\s\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string123 = /.{0,1000}posh\-update\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string124 = /.{0,1000}process_mimikatz.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string125 = /.{0,1000}pslo\s.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string126 = /.{0,1000}removeexe\-persistence.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string127 = /.{0,1000}remove\-persistence.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string128 = /.{0,1000}remove\-persistence\-cron.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string129 = /.{0,1000}runas\-netonly\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string130 = /.{0,1000}run\-dll\sSharpSploit.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string131 = /.{0,1000}safetydump.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string132 = /.{0,1000}seatbelt\s\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string133 = /.{0,1000}seatbelt\sall.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string134 = /.{0,1000}set\-killdate\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string135 = /.{0,1000}set\-pushover\-applicationtoken.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string136 = /.{0,1000}set\-pushover\-userkeys.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string137 = /.{0,1000}shadowcopy\senum.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string138 = /.{0,1000}Sharp_v4_x64.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string139 = /.{0,1000}Sharp_v4_x86.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string140 = /.{0,1000}sharpapplocker.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string141 = /.{0,1000}sharpchromium\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string142 = /.{0,1000}sharpcookiemonster.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string143 = /.{0,1000}sharpedrchecker.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string144 = /.{0,1000}sharphound\s\-.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string145 = /.{0,1000}sharpps\s\$psversiontable.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string146 = /.{0,1000}sharpps\sget\-process.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string147 = /.{0,1000}sharpsc\s.{0,1000}cmd.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string148 = /.{0,1000}sharptelnet\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string149 = /.{0,1000}sharpweb\sall.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string150 = /.{0,1000}sharpwmi\saction\=.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string151 = /.{0,1000}standin\s\-\-asrep.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string152 = /.{0,1000}standin\s\-\-dc.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string153 = /.{0,1000}standin\s\-\-delegation.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string154 = /.{0,1000}standin\s\-\-group\s.{0,1000}Domain\sAdmins.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string155 = /.{0,1000}standin\s\-\-object\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string156 = /.{0,1000}standin\s\-\-spn.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string157 = /.{0,1000}startanotherimplant.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string158 = /.{0,1000}startdaisy.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string159 = /.{0,1000}start\-keystrokes.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string160 = /.{0,1000}start\-keystrokes\-writefile.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string161 = /.{0,1000}start\-process\sntdsutil\.exe\s.{0,1000}create\sfull.{0,1000}.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string162 = /.{0,1000}stopdaisy.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string163 = /.{0,1000}stop\-keystrokes.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string164 = /.{0,1000}sweetpotato\s\-p.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string165 = /.{0,1000}timestomp\sc:.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string166 = /.{0,1000}unhide\-implant.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string167 = /.{0,1000}XOR\-Payloads\.py.{0,1000}/ nocase ascii wide
        // Description: pipe name from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string168 = /\\jaccdpqnvbrrxlaf.{0,1000}/ nocase ascii wide
        // Description: pipe name from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string169 = /\\Posh.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string170 = /posh\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string171 = /runof\s.{0,1000}\.o.{0,1000}/ nocase ascii wide
        // Description: keywords from poshc2 usage - a proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
        // Reference: https://github.com/nettitude/PoshC2
        $string172 = /runpe\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
