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
        $string1 = /\sPayloadType\.BIND_TCP/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string2 = /\sSharpC2/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string3 = /\/C2Frame\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string4 = /\/C2Profiles\// nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string5 = /\/Client\/Commands\/Enumeration\.yaml/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string6 = /\/Client\/Commands\/Execution\.yaml/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string7 = /\/Client\/Commands\/Injection\.yaml/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string8 = /\/Client\/Commands\/Lateral\.yaml/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string9 = /\/Client\/Commands\/Tokens\.yaml/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string10 = /\/Client\/Pages\/Drones\.razor/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string11 = /\/Client\/Pages\/Payloads\.razor/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string12 = /\/Client\/Pages\/Pivots\.razor/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string13 = /\/Drones\/SleepDialogue\.razor/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string14 = /\/ExeStager\// nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string15 = /\/ExternalC2\// nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string16 = /\/IPayloadService\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string17 = /\/PeerToPeerService\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string18 = /\/SharpC2/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string19 = /\/stager\.ps1/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string20 = /\/teamserver\-linux\.tar\.gz/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string21 = /\/teamserver\-win\.zip/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string22 = /\\SharpC2/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string23 = /\\stager\.ps1/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string24 = /\\teamserver\-win\.zip/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string25 = /192\.168\.1\.229\sPassw0rd\!/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string26 = /50050\/SharpC2/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string27 = /5E8106A6F89B053ED91C723D5D4CAE3FFC15F1CE/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string28 = /87904247\-C363\-4F12\-A13A\-3DA484913F9E/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string29 = /91EA50CD\-E8DF\-4EDF\-A765\-75354643BD0D/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string30 = /C2ProfileResponse\.cs/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string31 = /com\.rastamouse\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string32 = /Commands\/DcomCommand\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string33 = /Commands\/DroneCommand\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string34 = /Commands\/ExecuteAssembly\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string35 = /Commands\/KillProcess\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string36 = /Commands\/ListProcesses\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string37 = /Commands\/PowerShellImport\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string38 = /Commands\/PrintWorkingDirectory\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string39 = /Commands\/PsExecCommand\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string40 = /Commands\/RevToSelf\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string41 = /Commands\/RunPe\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string42 = /Commands\/SetSleep\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string43 = /Commands\/Shell\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string44 = /Commands\/ShInject\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string45 = /Commands\/ShSpawn\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string46 = /Commands\/StealToken\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string47 = /Commands\/StopDrone\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string48 = /Commands\/TakeScreenshot\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string49 = /Commands\/WhoAmI\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string50 = /Commands\/WinRmCommand\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string51 = /Commands\/WmiCommand\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string52 = /DE7B9E6B\-F73B\-4573\-A4C7\-D314B528CFCB/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string53 = /demo\-client\.exe\s/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string54 = /demo\-controller\.exe\s/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string55 = /exe_stager\.exe/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string56 = /ExeStager\.csproj/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string57 = /ExternalC2\.Net/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string58 = /ExternalC2\.Net\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string59 = /ExternalC2\\/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string60 = /GenerateReverseTcpDrone/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string61 = /http.{0,1000}127\.0\.0\.1\:50050/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string62 = /http.{0,1000}localhost\:50050/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string63 = /IPeerToPeerService\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string64 = /IReversePortForwardService\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string65 = /PayloadFormat\.ASSEMBLY/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string66 = /PayloadFormat\.DLL/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string67 = /PayloadFormat\.EXE/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string68 = /PayloadFormat\.POWERSHELL/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string69 = /PayloadFormat\.SHELLCODE/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string70 = /PayloadFormat\.SVC_EXE/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string71 = /PayloadService\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string72 = /PayloadType\.BIND_PIPE/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string73 = /PayloadType\.EXTERNAL/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string74 = /PayloadType\.HTTP/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string75 = /PayloadType\.REVERSE_TCP/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string76 = /PELoader\/PeLoader\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string77 = /rasta\-mouse\/SharpC2/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string78 = /Resources\/drone\.dll/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string79 = /SharpC2\s/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string80 = /SharpC2.{0,1000}\.cs/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string81 = /SharpC2.{0,1000}\.exe/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string82 = /sharpc2.{0,1000}client\-windows\.zip/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string83 = /SharpC2\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string84 = /SharpC2\.API/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string85 = /SharpC2Event/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string86 = /SharpC2Hub/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string87 = /SharpC2Webhook/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string88 = /Stagers\\ExeStager\\/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string89 = /Stagers\\SvcStager\\/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string90 = /svc_stager\.exe/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string91 = /TeamServer\.C2Profiles/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string92 = /TeamServer\/Filters\/InjectionFilters/ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string93 = /TeamServer\/Pivots\/.{0,1000}\./ nocase ascii wide
        // Description: Command and Control Framework written in C#
        // Reference: https://github.com/rasta-mouse/SharpC2
        $string94 = /TeamServer\\TeamServer\./ nocase ascii wide

    condition:
        any of them
}
