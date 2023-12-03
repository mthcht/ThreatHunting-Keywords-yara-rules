rule SharpC2
{
    meta:
        description = "Detection patterns for the tool 'SharpC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string1 = /.{0,1000}\sPayloadType\.BIND_TCP.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string2 = /.{0,1000}\sSharpC2.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string3 = /.{0,1000}\/C2Frame\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string4 = /.{0,1000}\/C2Profiles\/.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string5 = /.{0,1000}\/Client\/Commands\/Enumeration\.yaml.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string6 = /.{0,1000}\/Client\/Commands\/Execution\.yaml.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string7 = /.{0,1000}\/Client\/Commands\/Injection\.yaml.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string8 = /.{0,1000}\/Client\/Commands\/Lateral\.yaml.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string9 = /.{0,1000}\/Client\/Commands\/Tokens\.yaml.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string10 = /.{0,1000}\/Client\/Pages\/Drones\.razor.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string11 = /.{0,1000}\/Client\/Pages\/Payloads\.razor.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string12 = /.{0,1000}\/Client\/Pages\/Pivots\.razor.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string13 = /.{0,1000}\/Drones\/SleepDialogue\.razor.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string14 = /.{0,1000}\/ExeStager\/.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string15 = /.{0,1000}\/ExternalC2\/.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string16 = /.{0,1000}\/IPayloadService\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string17 = /.{0,1000}\/PeerToPeerService\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string18 = /.{0,1000}\/SharpC2.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string19 = /.{0,1000}\/stager\.ps1.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string20 = /.{0,1000}\/teamserver\-linux\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string21 = /.{0,1000}\/teamserver\-win\.zip.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string22 = /.{0,1000}\\SharpC2.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string23 = /.{0,1000}\\stager\.ps1.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string24 = /.{0,1000}\\teamserver\-win\.zip.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string25 = /.{0,1000}192\.168\.1\.229\sPassw0rd\!.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string26 = /.{0,1000}50050\/SharpC2.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string27 = /.{0,1000}5E8106A6F89B053ED91C723D5D4CAE3FFC15F1CE.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string28 = /.{0,1000}87904247\-C363\-4F12\-A13A\-3DA484913F9E.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string29 = /.{0,1000}91EA50CD\-E8DF\-4EDF\-A765\-75354643BD0D.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string30 = /.{0,1000}C2ProfileResponse\.cs.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string31 = /.{0,1000}com\.rastamouse\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string32 = /.{0,1000}Commands\/DcomCommand\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string33 = /.{0,1000}Commands\/DroneCommand\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string34 = /.{0,1000}Commands\/ExecuteAssembly\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string35 = /.{0,1000}Commands\/KillProcess\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string36 = /.{0,1000}Commands\/ListProcesses\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string37 = /.{0,1000}Commands\/PowerShellImport\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string38 = /.{0,1000}Commands\/PrintWorkingDirectory\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string39 = /.{0,1000}Commands\/PsExecCommand\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string40 = /.{0,1000}Commands\/RevToSelf\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string41 = /.{0,1000}Commands\/RunPe\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string42 = /.{0,1000}Commands\/SetSleep\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string43 = /.{0,1000}Commands\/Shell\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string44 = /.{0,1000}Commands\/ShInject\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string45 = /.{0,1000}Commands\/ShSpawn\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string46 = /.{0,1000}Commands\/StealToken\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string47 = /.{0,1000}Commands\/StopDrone\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string48 = /.{0,1000}Commands\/TakeScreenshot\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string49 = /.{0,1000}Commands\/WhoAmI\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string50 = /.{0,1000}Commands\/WinRmCommand\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string51 = /.{0,1000}Commands\/WmiCommand\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string52 = /.{0,1000}DE7B9E6B\-F73B\-4573\-A4C7\-D314B528CFCB.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string53 = /.{0,1000}demo\-client\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string54 = /.{0,1000}demo\-controller\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string55 = /.{0,1000}exe_stager\.exe.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string56 = /.{0,1000}ExeStager\.csproj.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string57 = /.{0,1000}ExternalC2\.Net.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string58 = /.{0,1000}ExternalC2\.Net\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string59 = /.{0,1000}ExternalC2\\.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string60 = /.{0,1000}GenerateReverseTcpDrone.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string61 = /.{0,1000}http.{0,1000}127\.0\.0\.1:50050.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string62 = /.{0,1000}http.{0,1000}localhost:50050.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string63 = /.{0,1000}IPeerToPeerService\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string64 = /.{0,1000}IReversePortForwardService\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string65 = /.{0,1000}PayloadFormat\.ASSEMBLY.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string66 = /.{0,1000}PayloadFormat\.DLL.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string67 = /.{0,1000}PayloadFormat\.EXE.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string68 = /.{0,1000}PayloadFormat\.POWERSHELL.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string69 = /.{0,1000}PayloadFormat\.SHELLCODE.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string70 = /.{0,1000}PayloadFormat\.SVC_EXE.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string71 = /.{0,1000}PayloadService\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string72 = /.{0,1000}PayloadType\.BIND_PIPE.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string73 = /.{0,1000}PayloadType\.EXTERNAL.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string74 = /.{0,1000}PayloadType\.HTTP.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string75 = /.{0,1000}PayloadType\.REVERSE_TCP.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string76 = /.{0,1000}PELoader\/PeLoader\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string77 = /.{0,1000}rasta\-mouse\/SharpC2.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string78 = /.{0,1000}Resources\/drone\.dll.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string79 = /.{0,1000}SharpC2\s.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string80 = /.{0,1000}SharpC2.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string81 = /.{0,1000}SharpC2.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string82 = /.{0,1000}sharpc2.{0,1000}client\-windows\.zip.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string83 = /.{0,1000}SharpC2\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string84 = /.{0,1000}SharpC2\.API.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string85 = /.{0,1000}SharpC2Event.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string86 = /.{0,1000}SharpC2Hub.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string87 = /.{0,1000}SharpC2Webhook.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string88 = /.{0,1000}Stagers\\ExeStager\\.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string89 = /.{0,1000}Stagers\\SvcStager\\.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string90 = /.{0,1000}svc_stager\.exe.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string91 = /.{0,1000}TeamServer\.C2Profiles.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string92 = /.{0,1000}TeamServer\/Filters\/InjectionFilters.{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string93 = /.{0,1000}TeamServer\/Pivots\/.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string94 = /.{0,1000}TeamServer\\TeamServer\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
