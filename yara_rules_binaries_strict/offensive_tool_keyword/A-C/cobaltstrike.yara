rule cobaltstrike
{
    meta:
        description = "Detection patterns for the tool 'cobaltstrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cobaltstrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1 = /\s\$exploit_oneliner/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2 = /\s\$payload_oneliner\s/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string3 = /\s\.beacon_keys\s\-/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string4 = /\s\/NAME\:.{0,100}\s\/KILL/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string5 = /\s\/PID\:.{0,100}\s\/DRIVER\:/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string6 = /\s\/PID\:.{0,100}\s\/KILL/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string7 = /\s\/ticket\:.{0,100}\s\/service\:.{0,100}\s\/targetdomain\:.{0,100}\s\/targetdc\:/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string8 = /\s\/user\:.{0,100}\s\/password\:.{0,100}\s\/enctype\:.{0,100}\s\/opsec\s\/ptt/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string9 = /\s1\.2\.3\.4\:8080/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string10 = " 4444 meter" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string11 = " 4444 shell" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string12 = " amsi_disable " nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string13 = /\sarp\.x64\.o/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string14 = " --assemblyargs AntiVirus" nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string15 = " --assemblyargs AppLocker" nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string16 = " base64_encode_shellcode" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string17 = /\sbeacon\.dll/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string18 = " bof_allocator " nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string19 = " bof_reuse_memory " nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string20 = " -BOFBytes " nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string21 = " BOFNET " nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string22 = /\sBofRunner\(/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string23 = /\sbuild\sDent\.go/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string24 = " build_letmeout" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string25 = /\sBypassUac.{0,100}\.bat/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string26 = /\sBypassUac.{0,100}\.dll/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string27 = /\sBypassUac.{0,100}\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string28 = /\s\-c\sCredEnum\.c/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string29 = " chrome logindata " nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string30 = " chrome masterkey " nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string31 = " -cobalt " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string32 = " cobaltstrike" nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string33 = " CoffeeExecuteFunction" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string34 = /\scom\.blackh4t/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string35 = " CrossC2 Listener" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string36 = /\sCrossC2\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string37 = " CrossC2Kit " nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string38 = /\sDelegationBOF\.c\s/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string39 = /\sdelegationx64\.o/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string40 = /\sdelegationx86\.o/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string41 = /\sDesertFox\.go/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string42 = /\sdetect\-hooks\.c\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string43 = " -dns_stager_prepend " nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string44 = " -dns_stager_subhost " nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string45 = /\s\-\-dotnetassembly\s.{0,100}\s\-\-amsi/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string46 = /\s\-\-dotnetassembly\s.{0,100}\s\-\-appdomain\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string47 = /\s\-\-dotnetassembly\s.{0,100}\s\-\-assemblyargs\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string48 = /\s\-\-dotnetassembly\s.{0,100}\s\-\-mailslot/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string49 = /\s\-\-dotnetassembly\s.{0,100}\s\-\-pipe\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string50 = " DraytekScan" nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string51 = " dump_memory64" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string52 = " edge logindata " nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string53 = " edge masterkey " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string54 = " EfsPotato" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string55 = /\sexclusion\.c\s\/Fodefender\.o/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string56 = " -FakeCmdLine " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string57 = " FileZillaPwd" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string58 = /\sforgeTGT\(/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string59 = " FtpSniffer " nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string60 = " generate_my_dll" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string61 = " generatePayload" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string62 = " GetAppLockerPolicies" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string63 = " GetLsassPid" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string64 = /\sgophish\-.{0,100}\.zip/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string65 = " HackBrowserData" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string66 = " -hasbootstraphint " nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string67 = /\sHiddenDesktop\.cna/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string68 = /\shollow\.x64\./ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string69 = /\shostenum\.py\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string70 = " HTTPSniffer " nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string71 = /\s\-i\shavex\.profile\s/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string72 = " impacket " nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string73 = " -Injector NtMapViewOfSection" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string74 = " -Injector VirtualAllocEx" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string75 = " -isbeacon " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string76 = " JspShell ua" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string77 = " k8gege520 " nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string78 = /\skdbof\.cpp/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string79 = /\sLadon\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string80 = /\sLadon\.py/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string81 = " --load-shellcode " nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string82 = /\smalleable\.profile/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string83 = " malleable-c2-randomizer" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string84 = /\smemreader\.c\s/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string85 = " MemReader_BoF" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string86 = " ms17010 -i " nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string87 = " ms17010 -n " nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string88 = " NTLMv1 captured " nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string89 = " -o /share/payloads/" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string90 = " oxidfind -i " nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string91 = " oxidfind -n " nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string92 = " --payload-types all" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string93 = " --payload-types bin" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string94 = " --payload-types dll" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string95 = " --payload-types exe" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string96 = " --payload-types ps1" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string97 = " --payload-types py" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string98 = /\s\-\-payload\-types\ssvc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string99 = " --payload-types vbs" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string100 = " -PE_Clone " nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string101 = " Perform S4U constrained delegation abuse" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string102 = " pipename_stager " nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string103 = " -pipename_stager " nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string104 = " pyasn1 " nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string105 = /\spyasn1\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string106 = " rai-attack-dns" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string107 = " rai-attack-http" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string108 = " ReadFromLsass" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string109 = " -RealCmdLine " nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string110 = " rustbof " nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string111 = /\sScareCrow\.go/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string112 = /\sScareCrow\.go/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string113 = /\sSeriousSam\.Execute\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string114 = " SetMzLogonPwd " nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string115 = /\ssigflip\.c\s/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string116 = /\sSigFlip\.exe/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string117 = /\sSigFlip\.PE/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string118 = /\ssigflip\.x64\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string119 = /\ssigflip\.x86\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string120 = " SigLoader " nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string121 = " Sigwhatever" nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string122 = /\sspawn\.x64\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string123 = /\sspawn\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string124 = " spawnto_x64 " nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string125 = " spawnto_x86 " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string126 = /\sSpoolFool\s.{0,100}\.dll/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string127 = /\sStayKit\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string128 = /\sstriker\.py/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string129 = " SweetPotato by @_EthicalChaos" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string130 = " SysWhispers" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string131 = " TikiLoader" nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string132 = /\sTokenStrip\.c\s/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string133 = /\sTokenStripBOF\.o\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string134 = " TSCHRPCAttack" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string135 = /\s\-urlcache\s.{0,100}\/debase64\// nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string136 = /\s\-wordlist\s.{0,100}\s\-spawnto\s/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string137 = " WriteToLsass" nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string138 = " xpipe" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string139 = /\$C2_SERVER/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string140 = /\.\/c2lint\s/
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string141 = /\.\/Dent\s\-/
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string142 = /\.\/manjusaka/
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string143 = /\.\/ScareCrow\s/
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string144 = /\.\/SourcePoint\s/
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string145 = /\.admin\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string146 = /\.api\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string147 = /\.apps\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string148 = /\.beta\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string149 = /\.blog\.123456\./ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string150 = /\.cobaltstrike/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string151 = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string152 = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string153 = /\.com\/dcsync\// nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string154 = /\.dev\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string155 = /\.events\.123456\./ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string156 = /\.exe\s.{0,100}\s\-eventlog\s.{0,100}Key\sManagement\sService/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string157 = /\.exe\s.{0,100}\s\-\-source\sPersistence/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string158 = /\.feeds\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string159 = /\.files\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string160 = /\.forums\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string161 = /\.ftp\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string162 = /\.go\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string163 = /\.groups\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string164 = /\.help\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string165 = /\.imap\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string166 = /\.img\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string167 = /\.kb\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string168 = /\.lists\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string169 = /\.live\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string170 = /\.m\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string171 = /\.mail\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string172 = /\.media\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string173 = /\.mobile\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string174 = /\.mysql\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string175 = /\.news\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string176 = /\.photos\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string177 = /\.pic\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string178 = /\.pipename_stager/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string179 = /\.pop\.123456\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string180 = /\.py\s.{0,100}\s\-\-teamserver\s/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string181 = /\.py\s127\.0\.0\.1\s50050\slogtracker\spassword/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string182 = /\.py.{0,100}\s\-\-payload\s.{0,100}\.ps1/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string183 = /\.py.{0,100}\s\-service\-name\s.{0,100}\s\-hashes\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string184 = /\.resources\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string185 = /\.search\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string186 = /\.secure\.123456\./ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string187 = /\.sharpgen\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string188 = /\.sites\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string189 = /\.smtp\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string190 = /\.ssl\.123456\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string191 = /\.stage\.123456\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string192 = /\.stage\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string193 = /\.static\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string194 = /\.status\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string195 = /\.store\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string196 = /\.support\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string197 = /\.videos\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string198 = /\.vpn\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string199 = /\.webmail\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string200 = /\.wiki\.123456\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string201 = /\/\.aggressor\.prop/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string202 = /\/\.ssh\/RAI\.pub/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string203 = "//StaticSyscallsDump/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string204 = "/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string205 = "/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1" nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string206 = /\/AceLdr\.cna/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string207 = "/adcs_enum/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string208 = /\/adcs_request\/adcs_request\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string209 = /\/adcs_request\/CertCli\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string210 = /\/adcs_request\/certenroll\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string211 = /\/adcs_request\/CertPol\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string212 = /\/AddUser\-Bof\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string213 = "/AddUser-Bof/" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string214 = /\/AggressiveClean\.cna/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string215 = /\/aggressor\/.{0,100}\.java/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string216 = "/aggressor-powerview" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string217 = "/AggressorScripts" nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string218 = "/AggressorScripts" nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string219 = "/AggressorScripts" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string220 = "/agscript "
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string221 = "/agscript " nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string222 = /\/Alaris\.sln/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string223 = /\/ANGRYPUPPY\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string224 = "/anthemtotheego/CredBandit" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string225 = /\/artifactor\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string226 = "/ase_docker/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string227 = /\/asprox\.profile/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string228 = /\/asprox\.profile/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string229 = /\/ASRenum\.cpp/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string230 = /\/ASRenum\.cs/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string231 = "/ASRenum-BOF" nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string232 = /\/assets\/bin2uuids_file\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string233 = "/AttackServers/" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string234 = /\/auth\/cc2_auth\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string235 = "/awesome-pentest" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string236 = /\/backoff\.profile/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string237 = "/backstab_src/" nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string238 = "/BackupPrivSam/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string239 = /\/bazarloader\.profile/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string240 = "/beacon_compatibility" nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string241 = /\/beacon_compatibility\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string242 = "/beacon_funcs/" nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string243 = "/beacon_health_check/" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string244 = "/beacon_http/" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string245 = /\/beacon_notify\.cna/ nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string246 = /\/beaconhealth\.cna/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string247 = "/beacon-injection/" nocase ascii wide
        // Description: Cobaltstrike beacon object files
        // Reference: https://github.com/realoriginal/beacon-object-file
        $string248 = "/beacon-object-file" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string249 = /\/BeaconTool\.java/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string250 = "/bin/AceLdr"
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string251 = /\/bin\/Sleeper\.o/
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string252 = "/bluscreenofjeff/" nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string253 = /\/bof\.h/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string254 = /\/BOF\.NET\// nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string255 = /\/bof\.nim/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string256 = /\/bof\.x64\.o/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string257 = /\/bof\.x64\.o/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string258 = /\/bof\.x86\.o/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string259 = /\/bof\.x86\.o/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string260 = /\/bof\/bof\.c/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string261 = /\/bof\/bof\.vcxproj/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string262 = "/bof/IABOF" nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string263 = /\/bof\/IAStart\.asm/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string264 = "/BOF-Builder" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string265 = "/bof-collection/" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string266 = "/BOFNETExamples/" nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string267 = "/BOF-RegSave" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string268 = /\/BofRunner\.cs/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string269 = /\/BOFs\.git/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string270 = "/bof-vs-template/" nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string271 = "/bof-vs-template/" nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string272 = "/boku7/spawn" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string273 = "/boku7/whereami/" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string274 = /\/BokuLoader\.c/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string275 = /\/BokuLoader\.h/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string276 = "/BokuLoader/" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string277 = /\/BooExecutor\.cs/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string278 = "/bq1iFEP2/assert/dll/" nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string279 = "/bq1iFEP2/assert/exe/" nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string280 = /\/breg\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string281 = /\/breg\.x86\.o/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string282 = "/build/encrypted_shellcode" nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string283 = "/build/formatted_shellcode" nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string284 = "/build/shellcode" nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string285 = "/BuildBOFs/" nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string286 = /\/burpee\.py/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string287 = "/BUYTHEAPTDETECTORNOW" nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string288 = "/BypassAV/" nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string289 = "/bypassAV-1/" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string290 = "/C2concealer" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string291 = /\/c2profile\./ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string292 = /\/c2profile\.go/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string293 = "/C2script/" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string294 = /\/cc2_frp\./ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string295 = /\/client\/bof\/.{0,100}\.asm/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string296 = /\/clipboardinject\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string297 = "/clipboardinject/" nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string298 = /\/clipmon\/clipmon\.sln/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string299 = "/clipmon/dll/" nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string300 = /\/cna\/pipetest\.cna/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string301 = /\/cobaltclip\.c/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string302 = /\/cobaltclip\.o/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string303 = "/Cobalt-Clip/" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string304 = "/cobaltstrike" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string305 = "/cobalt-strike" nocase ascii wide
        // Description: alternative to the Cobalt Strike Beacon
        // Reference: https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon
        $string306 = /\/CobaltStrike_OpenBeacon\.git/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string307 = /\/CoffeeLdr\.c/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string308 = "/CoffeeLdr/" nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string309 = "/COFFLoader" nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string310 = "/COFFLoader2/" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string311 = "/com/blackh4t/" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string312 = /\/comfoo\.profile/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string313 = /\/CookieProcessor\.cs/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string314 = /\/core\/browser_darwin\.go/
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string315 = /\/core\/browser_linux\.go/
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string316 = /\/core\/browser_windows\.go/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string317 = "/Cracked5pider/" nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string318 = "/credBandit/" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string319 = /\/CredEnum\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string320 = /\/CredEnum\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string321 = /\/CredEnum\.h/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string322 = /\/CredPrompt\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string323 = /\/CredPrompt\/credprompt\.c/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string324 = /\/CrossC2\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string325 = "/CrossC2/" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string326 = "/CrossC2Kit" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string327 = "/CrossC2Kit/" nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string328 = "/CrossNet-Beta/" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string329 = "/crypt0p3g/" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string330 = "/cs2modrewrite/" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string331 = "/CS-BOFs/" nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string332 = "/CSharpWinRM" nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string333 = "/C--Shellcode" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string334 = /\/CS\-Loader\.go/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string335 = "/CS-Loader/" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string336 = "/csOnvps/" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string337 = "/csOnvps/" nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string338 = "/cs-rdll-ipc-example/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string339 = "/CS-Remote-OPs-BOF" nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string340 = "/cs-token-vault/" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string341 = /\/curl\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string342 = /\/curl\.x64\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string343 = /\/curl\.x86\.o/ nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string344 = "/custom_payload_generator/" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string345 = "/CWoNaJLBo/VTNeWw11212/" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string346 = "/CWoNaJLBo/VTNeWw11213/" nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string347 = "/DCOM Lateral Movement/" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string348 = /\/defender\-exclusions\/.{0,100}defender/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string349 = /\/defender\-exclusions\/.{0,100}exclusion/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string350 = "/DelegationBOF/" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string351 = /\/demo_bof\.c/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string352 = /\/Dent\/.{0,100}\/Loader\/Loader\.go/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string353 = /\/Dent\/Dent\.go/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string354 = "/Dent/Loader" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string355 = /\/DesertFox\/archive\/.{0,100}\.zip/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string356 = /\/detect\-hooks\.c/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string357 = /\/detect\-hooks\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string358 = /\/detect\-hooks\.h/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string359 = "/Detect-Hooks/" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string360 = /\/dist\/fw_walk\./ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string361 = "/DLL-Hijack" nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string362 = "/Doge-Loader/" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string363 = "/DotNet/SigFlip" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string364 = /\/dukes_apt29\.profile/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string365 = /\/dump_lsass\./ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string366 = /\/dumpert\.c/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string367 = "/Dumpert/" nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string368 = /\/dumpXor\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string369 = "/dumpXor/dumpXor" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string370 = /\/ElevateKit\/elevate\./ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string371 = "/ELFLoader/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string372 = /\/emotet\.profile/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string373 = /\/enableuser\/enableuser\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string374 = /\/enableuser\/enableuser\.x86\./ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string375 = /\/EnumCLR\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string376 = /\/enumerate\.cna/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string377 = /\/Erebus\/.{0,100}\.dll/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string378 = /\/Erebus\/.{0,100}\.exe/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string379 = /\/Erebus\-email\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string380 = /\/etumbot\.profile/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string381 = /\/etw\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string382 = /\/etw\.x64\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string383 = /\/etw\.x86\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string384 = "/EventViewerUAC/" nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string385 = "/EventViewerUAC/" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string386 = /\/evil\.cpp/ nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string387 = /\/exports_function_hid\.txt/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string388 = /\/fiesta\.profile/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string389 = /\/fiesta2\.profile/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string390 = /\/final_shellcode_size\.txt/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string391 = /\/FindModule\.c/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string392 = /\/FindObjects\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string393 = "/Fodetect-hooksx64" nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string394 = "/FuckThatPacker" nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string395 = "/G0ldenGunSec/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string396 = /\/gandcrab\.profile/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string397 = /\/geacon\.git/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string398 = /\/geacon\/.{0,100}beacon/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string399 = "/geacon_pro" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string400 = /\/get\-loggedon\/.{0,100}\.c/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string401 = /\/get\-system\/getsystem\.c/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string402 = "/GetWebDAVStatus_BOF/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string403 = /\/globeimposter\.profile/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string404 = "/guervild/BOFs" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string405 = /\/hancitor\.profile/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com/EspressoCake/HandleKatz_BOF
        $string406 = "/HandleKatz_BOF" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string407 = /\/HaryyUser\.exe/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string408 = /\/havex\.profile/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string409 = /\/HiddenDesktop\.git/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string410 = /\/hollow\.x64\./ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string411 = /\/hooks\/spoof\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string412 = /\/hostenum\.py/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string413 = /\/HouQing\/.{0,100}\/Loader\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string414 = "/injectAmsiBypass/" nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string415 = "/inject-assembly/" nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string416 = /\/injectEtw\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string417 = "/Injection/clipboard/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string418 = "/Injection/conhost/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string419 = "/Injection/createremotethread/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string420 = "/Injection/ctray/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string421 = "/Injection/dde/" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string422 = /\/Injection\/Injection\.cna/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string423 = "/Injection/kernelcallbacktable" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string424 = "/Injection/ntcreatethread" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string425 = "/Injection/ntcreatethread/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string426 = "/Injection/ntqueueapcthread" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string427 = "/Injection/setthreadcontext" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string428 = "/Injection/svcctrl/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string429 = "/Injection/tooltip/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string430 = "/Injection/uxsubclassinfo" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string431 = "/InlineWhispers" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string432 = /\/Internals\/Coff\.cs/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string433 = /\/Inveigh\.txt/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string434 = "/Invoke-Bof/" nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string435 = /\/Invoke\-HostEnum\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string436 = /\/jaff\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string437 = /\/jasperloader\.profile/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string438 = /\/K8_CS_.{0,100}_.{0,100}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string439 = "/k8gege/" nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string440 = "/k8gege/scrun/" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string441 = "/k8gege520" nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string442 = /\/kdstab\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string443 = /\/KDStab\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string444 = "/KDStab/" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string445 = /\/Kerbeus\-BOF\.git/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string446 = "/Kerbeus-BOF/"
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string447 = /\/KernelMii\.c/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string448 = /\/kronos\.profile/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string449 = /\/Ladon\.go/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string450 = /\/Ladon\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string451 = /\/Ladon\.py/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string452 = /\/Ladon\/Ladon\./ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string453 = "/Ladon/obj/x86" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string454 = "/LadonGo/" nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string455 = "/LetMeOutSharp/" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string456 = /\/lib\/ipLookupHelper\.py/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string457 = /\/loader\/x64\/Release\/loader\.exe/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string458 = /\/loadercrypt_.{0,100}\.php/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string459 = /\/logs\/.{0,100}\/becon_.{0,100}\.log/
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string460 = "/logs/beacon_log" nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string461 = "/lpBunny/bof-registry" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string462 = /\/lsass\/beacon\.h/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string463 = /\/magnitude\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string464 = "/malleable-c2" nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string465 = "/manjusaka/plugins" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string466 = "/MemReader_BoF/" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string467 = /\/mimipenguin\.c/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string468 = "/mimipenguin/" nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string469 = /\/minimal_elf\.h/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string470 = /\/Misc\/donut\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string471 = /\/Mockingjay_BOF\.git/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string472 = /\/Modules\/Exitservice\/uinit\.exe/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string473 = "/Mr-Un1k0d3r/" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string474 = "/Native/SigFlip/" nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string475 = "/nccgroup/nccfsas/" nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string476 = "/Needle_Sift_BOF/" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string477 = "/nettitude/RunOF/" nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string478 = /\/NetUser\.cpp/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string479 = /\/NetUser\.exe/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string480 = "/netuserenum/" nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string481 = "/Network/PortScan/" nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string482 = /\/No\-Consolation\.git/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string483 = "/ntlmrelayx/" nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string484 = /\/oab\-parse\/mspack\..{0,100}\.dll/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string485 = "/OG-Sadpanda/" nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string486 = "/On_Demand_C2/" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string487 = "/opt/implant/" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string488 = "/opt/rai/" nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string489 = "/optiv/Dent/" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string490 = /\/oscp\.profile/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string491 = "/outflanknl/" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string492 = "/output/payloads/" nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string493 = "/p292/Phant0m" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string494 = /\/package\/portscan\/.{0,100}\.go/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string495 = "/password/mimipenguin/" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string496 = "/payload_scripts" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string497 = "/payload_scripts/artifact" nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string498 = "/PersistBOF/" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string499 = "/PhishingServer/" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string500 = /\/pitty_tiger\.profile/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string501 = /\/PoolPartyBof\.c/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string502 = /\/PoolPartyBof\.git/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string503 = /\/PoolPartyBof\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string504 = /\/popCalc\.bin/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string505 = "/PortBender/" nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string506 = /\/portscan\.cna/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string507 = /\/POSeidon\.profile/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string508 = /\/PowerView\.cna/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string509 = /\/PowerView3\.cna/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string510 = "/PPEnum/" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string511 = /\/ppldump\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string512 = "/PPLDump_BOF/" nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string513 = /\/PrintMonitorDll\./ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string514 = "/PrintMonitorDll/" nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string515 = "/PrintSpoofer/" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string516 = "/PrivilegeEscalation/" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string517 = /\/proberbyte\.go/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string518 = /\/Proxy_Def_File_Generator\.cna/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string519 = /\/putter\.profile/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string520 = "/pyasn1/" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string521 = "/pycobalt-" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string522 = "/pycobalt/" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string523 = /\/pystinger\.zip/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string524 = /\/qakbot\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string525 = /\/quantloader\.profile/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string526 = /\/RAI\.git/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string527 = /\/ramnit\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string528 = /\/ratankba\.profile/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string529 = /\/raw_shellcode_size\.txt/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string530 = /\/RC4Payload32\.txt/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string531 = "/RCStep/CSSG/" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string532 = /\/readfile_bof\./ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string533 = "/Readfile_BoF/" nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string534 = "/red-team-scripts" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string535 = /\/RedWarden\.git/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string536 = /\/RegistryPersistence\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string537 = "/Registry-Recon/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string538 = "/Remote/adcs_request/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string539 = "/Remote/office_tokens/" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string540 = "/Remote/procdump/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string541 = "/Remote/ProcessDestroy/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string542 = "/Remote/ProcessListHandles/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string543 = "/Remote/schtaskscreate/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string544 = "/Remote/schtasksrun/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string545 = "/Remote/setuserpass/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string546 = "/Remote/setuserpass/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string547 = "/Remote/unexpireuser/" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string548 = /\/remotereg\.c/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string549 = /\/remotereg\.o/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string550 = "/RunOF/RunOF/" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string551 = /\/runshellcode\./ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string552 = "/S3cur3Th1sSh1t/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string553 = /\/saefko\.profile/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string554 = "/ScareCrow -I "
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string555 = /\/ScRunHex\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string556 = "/searchsploit" nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string557 = /\/Seatbelt\.txt/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string558 = /\/secinject\.c/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string559 = /\/self_delete\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string560 = /\/SeriousSam\.sln/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string561 = "/serverscan/CobaltStrike" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string562 = "/serverscan_Air" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string563 = "/serverscan_pro" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string564 = "/ServerScanForLinux/"
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string565 = "/ServerScanForWindows/" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string566 = "/ServerScanForWindows/PE" nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string567 = "/ServiceMove-BOF/" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string568 = /\/Services\/TransitEXE\.exe/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string569 = /\/setuserpass\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string570 = /\/setuserpass\.x86\./ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string571 = /\/SharpCalendar\/.{0,100}\./ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string572 = "/SharpCat/" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string573 = "/SharpCompile/" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string574 = /\/sharpcompile_.{0,100}\./ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string575 = "/SharpCradle/" nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string576 = "/SharpSword/SharpSword" nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string577 = "/ShellCode_Loader" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string578 = "/shspawnas/" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string579 = /\/sigflip\.x64\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string580 = /\/sigflip\.x86\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string581 = /\/SigLoader\.go/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string582 = "/SigLoader/" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string583 = /\/SilentClean\.exe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string584 = /\/SilentClean\/SilentClean\/.{0,100}\.cs/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string585 = /\/silentdump\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string586 = /\/silentdump\.h/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string587 = "/sleep_python_bridge/" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string588 = /\/Sleeper\/Sleeper\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string589 = /\/sleepmask\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string590 = /\/spawn\.git/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string591 = "/spoolsystem/SpoolTrigger/" nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string592 = /\/Spray\-AD\./ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string593 = "/Spray-AD/" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string594 = /\/src\/Sleeper\.cpp/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string595 = "/StaticSyscallsAPCSpawn/" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string596 = "/StaticSyscallsInject/" nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string597 = /\/StayKit\.cna/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string598 = /\/Staykit\/StayKit\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string599 = /\/striker\.py/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string600 = /\/string_of_paerls\.profile/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string601 = /\/suspendresume\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string602 = /\/suspendresume\.x86/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string603 = "/SweetPotato_CS" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string604 = "/SyscallsInject/" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string605 = /\/taidoor\.profile/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string606 = /\/tcpshell\.py/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string607 = /\/teamserver\.service/
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string608 = /\/test32\.dll/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string609 = /\/test64\.dll/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string610 = /\/tests\/test\-bof\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string611 = "/tevora-threat/PowerView" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string612 = /\/tgtParse\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string613 = /\/tgtParse\/tgtParse\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string614 = /\/ticketConverter\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string615 = "/TikiLoader/" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string616 = /\/TikiSpawn\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string617 = "/TikiSpawn/" nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string618 = "/TokenStripBOF" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string619 = "/tools/BeaconTool/" nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string620 = "/Tools/spoolsystem/" nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string621 = "/Tools/Squeak/Squeak" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string622 = /\/trick_ryuk\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string623 = /\/trickbot\.profile/ nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string624 = /\/UAC\-BOF\-Bonanza\.git/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string625 = "/UAC-SilentClean/" nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/Cobalt-Strike/unhook-bof
        $string626 = "/unhook-bof" nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string627 = "/unhook-bof" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string628 = "/UTWOqVQ132/" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string629 = "/vssenum/" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string630 = /\/WdToggle\.c/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string631 = /\/WdToggle\.h/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string632 = /\/webshell\/.{0,100}\.aspx/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string633 = /\/webshell\/.{0,100}\.jsp/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string634 = /\/webshell\/.{0,100}\.php/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string635 = /\/wifidump\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string636 = /\/WindowsVault\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string637 = /\/WindowsVault\.h/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string638 = /\/winrm\.cpp/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string639 = "/winrmdll" nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string640 = "/winrm-reflective-dll/" nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string641 = /\/Winsocky\.git/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string642 = "/WMI Lateral Movement/" nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string643 = "/wwlib/lolbins/" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string644 = /\/xen\-mimi\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string645 = /\/xor\/stager\.txt/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string646 = /\/xor\/xor\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string647 = "/xPipe/" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string648 = "/yanghaoi/_CNA" nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string649 = /\/zerologon\.cna/ nocase ascii wide
        // Description: cobaltstrike default content strings
        // Reference: https://www.cobaltstrike.com/
        $string650 = /\[\+\]\sPrivileged\sfile\scopy\ssuccess\!\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string651 = /\[\'spawnto\'\]/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string652 = /\\\\\.\\pipe\\bypassuac/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string653 = /\\\\\.\\pipe\\hashdump/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string654 = /\\\\\.\\pipe\\imposecost/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string655 = /\\\\\.\\pipe\\keylogger/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string656 = /\\\\\.\\pipe\\mimikatz/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string657 = /\\\\\.\\pipe\\netview/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string658 = /\\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string659 = /\\\\\.\\pipe\\portscan/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string660 = /\\\\\.\\pipe\\screenshot/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string661 = /\\\\\.\\pipe\\sshagent/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string662 = /\\\\\.pipe\\imposingcost/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string663 = /\\\\\\\\\.\\\\pipe\\\\bypassuac/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string664 = /\\\\\\\\\.\\\\pipe\\\\hashdump/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string665 = /\\\\\\\\\.\\\\pipe\\\\keylogger/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string666 = /\\\\\\\\\.\\\\pipe\\\\mimikatz/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string667 = /\\\\\\\\\.\\\\pipe\\\\netview/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string668 = /\\\\\\\\\.\\\\pipe\\\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string669 = /\\\\\\\\\.\\\\pipe\\\\portscan/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string670 = /\\\\\\\\\.\\\\pipe\\\\screenshot/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string671 = /\\\\\\\\\.\\\\pipe\\\\sshagent/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string672 = /\\\\GetWebDAVStatus\.exe/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string673 = /\\\\pipe\\\\DAV\sRPC\sSERVICE/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string674 = /\\8e8988b257e9dd2ea44ff03d44d26467b7c9ec16/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string675 = /\\asreproasting\.c/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string676 = /\\beacon\.exe/ nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string677 = /\\bypassuac\.txt/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string678 = /\\CrossC2\./ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string679 = /\\CROSSNET\\CROSSNET\\/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string680 = /\\dumpert\./ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string681 = /\\Dumpert\\/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string682 = /\\DumpShellcode/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string683 = /\\dumpXor\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string684 = /\\dumpXor\\x64\\/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string685 = /\\ELF\\portscan/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string686 = /\\ELF\\serverscan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string687 = /\\evil\.dll/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string688 = /\\geacon\\tools\\BeaconTool\\/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string689 = /\\GetWebDAVStatus\\/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string690 = /\\GetWebDAVStatus_x64/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string691 = /\\HackBrowserData/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string692 = /\\HiddenDesktop\\/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string693 = /\\HostEnum\.ps1/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string694 = /\\kdstab\.exe/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string695 = /\\kerberoasting\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string696 = /\\Kerbeus\-BOF\\/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string697 = /\\Koh\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string698 = /\\Koh\.pdb/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string699 = /\\Koh\\Koh\./ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string700 = /\\Ladon\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string701 = /\\Ladon\.ps1/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string702 = /\\LogonScreen\.exe/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string703 = /\\lsass\.dmp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string704 = /\\Mockingjay_BOF\./ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string705 = /\\No\-Consolation\\source\\/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string706 = /\\portbender\./ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string707 = /\\PowerView\.cna/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string708 = /\\PowerView\.exe/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string709 = /\\PowerView\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string710 = /\\PowerView3\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string711 = /\\RunBOF\.exe/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string712 = /\\RunOF\.exe/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string713 = /\\RunOF\\bin\\/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string714 = /\\samantha\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string715 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string716 = /\\SigFlip\.exe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string717 = /\\SilentClean\.exe/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string718 = /\\StayKit\.cna/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string719 = /\\systemic\.txt/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string720 = /\\TASKSHELL\.EXE/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string721 = /\\TikiCompiler\.txt/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string722 = /\\TikiService\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string723 = /\\TikiSpawn\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string724 = /\\tikispawn\.xml/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string725 = /\\TikiTorch\\Aggressor/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string726 = /\\xpipe\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string727 = /\\xpipe\.o/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string728 = /\]\scompile\sgeacon\swith\sthe\spublic\skey\sfrom\s\.beacon_keys/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string729 = /\]\suse\sthe\saes\skey\sfrom\sthe\sbeacon\'s\sonline\sinfo\sto\sencrypt\stransfer\sdata\s\(base64\sformat/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string730 = /\]\suse\sthe\spublic\skey\sfrom\s\.beacon_keys\sto\sdecrypt\sthe\sbeacon\'s\sonline\sinfo/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string731 = /\]\sUsing\sKohPipe\s\s\s\s/ nocase ascii wide
        // Description: cobaltstrike default content strings
        // Reference: https://www.cobaltstrike.com/
        $string732 = /\]\sWrote\shijack\sDLL\sto\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string733 = "_cobaltstrike" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string734 = "_find_sharpgen_dll" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string735 = "_pycobalt_" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string736 = /_tcp_cc2\(/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string737 = /_udp_cc2\(/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string738 = /\<CoffeLdr\.h\>/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string739 = "08114a94779a336824a0c62c3d19622fb39aae355962d36a97ba1423a4d6bfcf" nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string740 = "0xEr3bus/PoolPartyBof" nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string741 = "0xthirteen/MoveKit" nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string742 = "0xthirteen/StayKit" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string743 = "4d5350c8-7f8c-47cf-8cde-c752018af17e" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string744 = "5072c4beef28abdb0c53a1f33836facec9e651f6384dedb62611dc3a4d2403d5" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string745 = "516280565958" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string746 = "516280565959" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string747 = "518d6457e2d3e20e470f20b6399ce0f0ff5091dc6d2a0826d658247832ff4a8c" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string748 = "5a40f11a99d0db4a0b06ab5b95c7da4b1c05b55a99c7c443021bff02c2cf93145c53ff5b" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string749 = "5e98194a01c6b48fa582a6a9fcbb92d6" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string750 = "5f9bb909c87cb452a6edbd9da0b5cfdd3f729d7393cf9f7f94e3b731503d072d" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string751 = "6191bb09381c0a8a09db8e7753b7ef89084aaf7557e1605cfeb3abdca258f3ad" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string752 = "6290c67de059c8c86e7051348a1fd0934c8bdf6b9badb539a878a1801b0431d6" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string753 = "6e7645c4-32c5-4fe3-aabf-e94c2f4370e7" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string754 = "713724C3-2367-49FA-B03F-AB4B336FB405" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string755 = "732211ae-4891-40d3-b2b6-85ebd6f5ffff" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string756 = "76318bcd19b5f3efe0e51c77593bccd6804c6a30b95c4c51ec528c30c7faca83" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string757 = /7CFC52\.dll/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string758 = /7CFC52CD3F\.dll/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string759 = "913d774e5cf0bfad4adfa900997f7a1a" nocase ascii wide
        // Description: alternative to the Cobalt Strike Beacon
        // Reference: https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon
        $string760 = "95502b5e-5763-4ec5-a64c-1e9e33409e2f" nocase ascii wide
        // Description: alternative to the Cobalt Strike Beacon
        // Reference: https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon
        $string761 = "9a7dc8a314e69eca7cfcd77046061485331e43c3c153ab9953e9c75f9e3db7d3" nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string762 = /AceLdr\..{0,100}\.bin/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string763 = /AceLdr\.zip/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string764 = /adcs_enum\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string765 = /adcs_enum_com\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string766 = /adcs_enum_com2\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string767 = /AddUser\-Bof\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string768 = /AddUser\-Bof\.git/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string769 = /AddUser\-Bof\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string770 = /AddUser\-Bof\.x64/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string771 = /AddUser\-Bof\.x86/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string772 = /AddUserToDomainGroup\s.{0,100}Domain\sAdmins/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string773 = /AddUserToDomainGroup\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string774 = /AddUserToDomainGroup\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string775 = "Adminisme/ServerScan/" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string776 = "ag_load_script" nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string777 = /AggressiveProxy\.cna/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string778 = /aggressor\.beacons/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string779 = /aggressor\.bshell/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string780 = /aggressor\.cna/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string781 = /aggressor\.dialog/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string782 = /aggressor\.println/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string783 = /aggressor\.py/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string784 = "Aggressor/TikiTorch" nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string785 = "aggressor-scripts" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string786 = "ajpc500/BOFs" nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string787 = "Allocated shellcode memory in the target process: " nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string788 = "Alphabug_CS" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string789 = "Alphabug_CS" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string790 = "AlphabugX/csOnvps" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string791 = "AlphabugX/csOnvps" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string792 = /Already\sSYSTEM.{0,100}not\selevating/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string793 = /ANGRYPUPPY2\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string794 = "anthemtotheego/Detect-Hooks" nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string795 = "apokryptein/secinject" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string796 = "applocker_enum" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string797 = "applocker-enumerator" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string798 = /apt1_virtuallythere\.profile/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string799 = /arsenal_kit\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string800 = /artifact\.cna/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string801 = /artifact\.cna/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string802 = /artifact\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string803 = /artifact\.x64\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string804 = /artifact\.x86\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string805 = /artifact\.x86\.exe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string806 = "artifact_payload" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string807 = "artifact_stageless" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string808 = "artifact_stager" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string809 = /artifact32.{0,100}\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string810 = /artifact32\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string811 = /artifact32\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string812 = /artifact32big\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string813 = /artifact32big\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string814 = /artifact32svc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string815 = /artifact32svcbig\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string816 = /artifact64.{0,100}\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string817 = /artifact64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string818 = /artifact64\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string819 = /artifact64\.x64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string820 = /artifact64big\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string821 = /artifact64big\.x64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string822 = /artifact64svc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string823 = /artifact64svcbig\.exe/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string824 = /artifactbig64\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string825 = /artifactuac.{0,100}\.dll/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string826 = /asktgs\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string827 = /ASRenum\-BOF\./ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string828 = /asreproasting\.x64/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string829 = /Assemblies\/SharpMove\.exe/ nocase ascii wide
        // Description: Cobalt Strike BOFs
        // Reference: https://github.com/AttackTeamFamily/cobaltstrike-bof-toolset
        $string830 = /AttackTeamFamily.{0,100}\-bof\-toolset/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string831 = "ausecwa/bof-registry" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string832 = /auth\/cc2_ssh\./ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string833 = "Backdoor LNK" nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string834 = "--backdoor-all" nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string835 = "backdoorlnkdialog" nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string836 = /backstab\.x64\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string837 = /backstab\.x86\./ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string838 = /BackupPrivSAM\s\\\\/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string839 = /backupprivsam\./ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string840 = /BadPotato\.exe/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string841 = "bawait_upload" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string842 = "bawait_upload_raw" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string843 = "bblockdlls" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string844 = "bbrowserpivot" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string845 = "bbrowserpivot" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string846 = "bbypassuac" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string847 = "bcc2_setenv" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string848 = "bcc2_spawn" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string849 = "bcrossc2_load_dyn" nocase ascii wide
        // Description: Malleable C2 Profiles. A collection of profiles used in different projects using Cobalt Strike & Empire.
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string850 = /BC\-SECURITY.{0,100}Malleable/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string851 = "bdcsync" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string852 = "bdllinject" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string853 = "bdllinject" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string854 = "bdllload" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string855 = "bdllload" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string856 = "bdllspawn" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string857 = "bdllspawn" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string858 = "be041565c155ce5a9129e2d79a2c8d18acf4143a7f3aa2237c15a15a89b6625e" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string859 = "Beacon Payload Generator" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string860 = /beacon\..{0,100}winsrv\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string861 = /beacon\.CommandBuilder/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string862 = /beacon\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string863 = /beacon\.exe/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string864 = /beacon\.exe/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string865 = /beacon\.nim/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string866 = /Beacon\.Object\.File\.zip/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string867 = /beacon\.x64.{0,100}\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string868 = /beacon\.x64.{0,100}\.exe/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string869 = /beacon\.x64\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string870 = /beacon\.x86.{0,100}\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string871 = /beacon\.x86.{0,100}\.exe/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string872 = /beacon_api\.h/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string873 = "beacon_bottom " nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string874 = "Beacon_Com_Struct" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string875 = "beacon_command_describe" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string876 = "beacon_command_detail" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string877 = "beacon_command_register" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string878 = "beacon_commands" nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string879 = /beacon_compatibility\.c/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string880 = /beacon_compatibility\.h/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string881 = "beacon_elevator_describe" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string882 = "beacon_elevator_register" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string883 = "beacon_elevators" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string884 = "beacon_elevators" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string885 = "beacon_execute_job" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string886 = "beacon_exploit_describe" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string887 = "beacon_exploit_register" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string888 = /beacon_funcs\.c/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string889 = /beacon_funcs\.h/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string890 = /beacon_funcs\.x64\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string891 = /beacon_funcs\.x86\./ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string892 = /beacon_generate\.py/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string893 = "Beacon_GETPOST" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string894 = "beacon_host_script" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string895 = "beacon_host_script" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string896 = "beacon_inline_execute" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string897 = "beacon_keys -compile geacon_sourcecode_folder" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string898 = "beacon_log_clean" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string899 = /beacon_output_ps\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string900 = "beacon_print" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string901 = "BEACON_RDLL_" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string902 = "beacon_remote_exec_" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string903 = "beacon_remote_exec_method_describe" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string904 = "beacon_remote_exec_method_register" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string905 = "beacon_remote_exec_methods" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string906 = "beacon_remote_exploit" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string907 = "beacon_remote_exploit_arch" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string908 = "beacon_remote_exploit_describe" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string909 = "beacon_remote_exploit_register" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string910 = "beacon_remote_exploits" nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string911 = /beacon_smb\.exe/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string912 = "Beacon_Stage_p2_Stuct" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string913 = "beacon_stage_pipe" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string914 = "Beacon_Stage_Struct_p1" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string915 = "Beacon_Stage_Struct_p3" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string916 = "beacon_stage_tcp" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string917 = "beacon_stage_tcp" nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string918 = /beacon_test\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string919 = "beacon_top " nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string920 = "beacon_top_callback" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string921 = /BeaconApi\.cs/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string922 = "beacon-c2-go" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string923 = "BeaconCleanupProcess" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string924 = /BeaconConsoleWriter\.cs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string925 = "BeaconGetSpawnTo" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string926 = "BeaconGetSpawnTo" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string927 = "BeaconGetSpawnTo" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string928 = /beacongrapher\.py/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string929 = "BeaconInjectProcess" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string930 = "BeaconInjectProcess" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string931 = "BeaconInjectTemporaryProcess" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string932 = "BeaconInjectTemporaryProcess" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string933 = /BeaconJob\.cs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string934 = /BeaconJobWriter\.cs/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string935 = /beaconlogs\.json/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string936 = /beaconlogtracker\.py/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string937 = /BeaconNote\.cna/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string938 = /BeaconNotify\.cna/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string939 = /BeaconObject\.cs/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string940 = "BeaconOutputStreamW" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string941 = /BeaconOutputWriter\.cs/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string942 = /BeaconPrintf\(/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string943 = "BeaconPrintf" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string944 = "BeaconPrintToStreamW" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string945 = "BeaconSpawnTemporaryProcess" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string946 = "BeaconSpawnTemporaryProcess" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string947 = "BeaconTool -" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string948 = /BeaconTool\s\-i\sonline_info\.txt\s\-aes\sdecrypt/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string949 = /BeaconTool\/lib\/sleep\.jar/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string950 = "BeaconUseToken" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string951 = "bgetprivs" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string952 = "bhashdump" nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string953 = /bin\/bof_c\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string954 = /bin\/bof_nim\.o/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string955 = "bkerberos_ccache_use" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string956 = "bkerberos_ticket_purge" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string957 = "bkerberos_ticket_use" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string958 = "bkeylogger" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string959 = "blockdlls start" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string960 = "blockdlls stop" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string961 = "bloginuser" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string962 = "blogonpasswords" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string963 = "BOF prototype works!" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string964 = /bof.{0,100}\/CredEnum\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string965 = /BOF\/.{0,100}procdump\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string966 = "bof_allocator" nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string967 = /bof_helper\.py/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string968 = /bof_net_user\.c/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string969 = /bof_net_user\.o/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string970 = "bof_reuse_memory" nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string971 = "BOF2shellcode" nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string972 = /bof2shellcode\.py/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string973 = "BOF-DLL-Inject" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string974 = "bofentry::bof_entry" nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string975 = "BOF-ForeignLsass" nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string976 = /BOF\-IShellWindows\-DCOM\./ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string977 = "BofLdapSignCheck" nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string978 = /bofloader\.bin/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string979 = /bofnet.{0,100}SeriousSam\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string980 = /BOFNET\.Bofs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string981 = /bofnet\.cna/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string982 = /BOFNET\.csproj/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string983 = /BOFNET\.sln/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string984 = /bofnet_boo\s.{0,100}\.boo/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string985 = "bofnet_execute " nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string986 = /bofnet_execute\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string987 = "bofnet_init" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string988 = "bofnet_job " nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string989 = "bofnet_jobkill" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string990 = "bofnet_jobs" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string991 = "bofnet_jobstatus " nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string992 = "bofnet_list" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string993 = "bofnet_listassembiles" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string994 = /bofnet_load\s.{0,100}\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string995 = "bofnet_shutdown" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string996 = "BOFNET_Tests" nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string997 = "bofportscan " nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string998 = /bof\-quser\s.{0,100}\./ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string999 = /bof\-quser\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1000 = "bof-rdphijack" nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string1001 = "bof-regsave " nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1002 = "BofRunnerOutput" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1003 = /BOFs.{0,100}\/SyscallsSpawn\// nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1004 = "Bofs/AssemblyLoader" nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1005 = "bof-servicemove " nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1006 = "bof-trustedpath-uacbypass" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1007 = "boku_pe_customMZ" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1008 = "boku_pe_customPE" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1009 = "boku_pe_dll" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1010 = "boku_pe_mask_" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1011 = "boku_pe_MZ_from_C2Profile" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1012 = "boku_strrep" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1013 = "boku7/BokuLoader" nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string1014 = "boku7/HOLLOW" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1015 = /BokuLoader\.cna/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1016 = /BokuLoader\.exe/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1017 = /BokuLoader\.x64/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1018 = /BooExecutorImpl\.cs/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1019 = "bpassthehash" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1020 = "bpowerpick" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1021 = "bpsexec_command" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1022 = "bpsexec_command" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1023 = "bpsexec_psh" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1024 = "bpsinject" nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1025 = /breg\sadd\s.{0,100}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1026 = /breg\sdelete\s.{0,100}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1027 = /breg\squery\s.{0,100}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1028 = "breg_add_string_value" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1029 = "bremote_exec" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1030 = "browser_##" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1031 = "browserpivot " nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1032 = "brun_script_in_mem" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1033 = "brunasadmin" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1034 = "bshinject" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1035 = "bshinject" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1036 = "bshspawn" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1037 = "bsteal_token" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1038 = "bsteal_token" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1039 = /build\sSourcePoint\.go/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1040 = /build\/breg\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1041 = "build_c_shellcode" nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1042 = /BuildBOFs\.exe/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1043 = /BuildBOFs\.sln/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1044 = "Building Koh BOFs" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1045 = /bupload_raw.{0,100}\.dll/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1046 = /burp2malleable\./ nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1047 = "Bypass Success! Now impersonating the forged token" nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string1048 = /BypassAV\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1049 = /bypass\-pipe\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string1050 = "byt3bl33d3r/BOF-Nim" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1051 = /\-c\sBOF\.cpp\s\-o\sBOF\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1052 = /\-c\sBOF\.cpp\s\-o\sBOF\.x64\.o/ nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1053 = /C\:\\Temp\\poc\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1054 = /C\:\\Windows\\Temp\\move\.exe/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1055 = /C\:\\Windows\\Temp\\moveme\.exe/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1056 = /C\?\?\/generator\.cpp/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1057 = "c2lint " nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1058 = "C2ListenerPort" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1059 = /\-c2\-randomizer\.py/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1060 = "C2ReverseClint" nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1061 = "C2ReverseProxy" nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1062 = "C2ReverseServer" nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1063 = /C2script\/proxy\./ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1064 = "'c2server'" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1065 = "c5c2ca31085c518b48980da28238d622ba5bb77d0caf36bae116ad90c2a7920f" nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1066 = /CACTUSTORCH\.cna/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1067 = /CACTUSTORCH\.cs/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1068 = /CACTUSTORCH\.hta/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1069 = /CACTUSTORCH\.js/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1070 = /CACTUSTORCH\.vba/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1071 = /CACTUSTORCH\.vbe/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1072 = /CACTUSTORCH\.vbs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1073 = "CALLBACK_HASHDUMP" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1074 = "CALLBACK_KEYSTROKES" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1075 = "CALLBACK_NETVIEW" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1076 = "CALLBACK_PORTSCAN" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1077 = "CALLBACK_TOKEN_STOLEN" nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1078 = /CallBackDump.{0,100}dumpXor/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1079 = /CallbackDump\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1080 = /careCrow.{0,100}_linux_amd64/
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1081 = /cat\s.{0,100}\.bin\s\|\sbase64\s\-w\s0\s\>\s.{0,100}\.txt/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1082 = "cc2_keystrokes_" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1083 = /cc2_mimipenguin\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1084 = "cc2_portscan_" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1085 = /cc2_rebind_.{0,100}_get_recv/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1086 = /cc2_rebind_.{0,100}_get_send/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1087 = /cc2_rebind_.{0,100}_post_recv/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1088 = /cc2_rebind_.{0,100}_post_send/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1089 = "cc2_udp_server" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1090 = /cc2FilesColor\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1091 = /cc2ProcessColor\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1092 = /CCob\/BOF\.NET/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1093 = /cd\s\.\/whereami\//
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1094 = /ChatLadon\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1095 = /ChatLadon\.rar/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1096 = "check_and_write_IAT_Hook" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1097 = /check_function\sntdll\.dll\sEtwEventWrite/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1098 = "checkIfHiddenAPICall" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1099 = /chromeKey\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1100 = /chromeKey\.x86/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1101 = "chromiumkeydump" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1102 = "cHux014r17SG3v4gPUrZ0BZjDabMTY2eWDj1tuYdREBg" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1103 = /clipboardinject\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1104 = /clipboardinject\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1105 = /clipboardinject\.x86/ nocase ascii wide
        // Description: CLIPBRDWNDCLASS process injection technique(BOF) - execute beacon shellcode in callback
        // Reference: https://github.com/BronzeTicket/ClipboardWindow-Inject
        $string1106 = "ClipboardWindow-Inject" nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1107 = /clipmon\.sln/ nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1108 = "CmstpElevatedCOM" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1109 = "Cobalt Strike" nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1110 = /cobaltclip\.cna/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1111 = /cobaltclip\.exe/ nocase ascii wide
        // Description: cobaltstrike binary for windows - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network. While penetration tests focus on unpatched vulnerabilities and misconfigurations. these assessments benefit security operations and incident response.
        // Reference: https://www.cobaltstrike.com/
        $string1112 = "cobaltstrike" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1113 = "cobalt-strike" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1114 = /cobaltstrike\.store/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1115 = "Cobalt-Strike/bof_template" nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1116 = /CodeLoad\(shellcode\)/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1117 = /coff_definitions\.h/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1118 = /COFF_Loader\./ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1119 = "COFF_PREP_BEACON" nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1120 = /CoffeeLdr.{0,100}\sgo\s/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1121 = /CoffeeLdr\.x64\.exe/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1122 = /CoffeeLdr\.x86\.exe/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1123 = "COFFELDR_COFFELDR_H" nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1124 = /COFFLoader\./ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1125 = /COFFLoader64\.exe/ nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1126 = "ColorDataProxyUACBypass" nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1127 = /com_exec_go\(/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1128 = /com\-exec\.cna/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1129 = /common\.ReflectiveDLL/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1130 = "comnap_##" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1131 = "comnode_##" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1132 = "connormcgarr/tgtdelegation" nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1133 = /cookie_graber_x64\.o/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1134 = /cookie\-graber\.c/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1135 = /cookie\-graber_x64\.exe/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1136 = "Cookie-Graber-BOF" nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1137 = /CookieProcessor\.exe/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1138 = /covid19_koadic\.profile/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1139 = "crawlLdrDllList" nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1140 = /credBandit\s.{0,100}\soutput/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1141 = /credBandit\./ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1142 = "credBanditx64" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string1143 = /CredPrompt\/CredPrompt\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1144 = "cribdragg3r/Alaris" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1145 = /crimeware.{0,100}\/zeus\.profile/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1146 = "crisprss/PrintSpoofer" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1147 = /cross_s4u\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1148 = /cross_s4u\.x64\.o/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1149 = "CrossC2 beacon" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1150 = /CrossC2\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1151 = "crossc2_entry" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1152 = /crossc2_portscan\./ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1153 = /crossc2_serverscan\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1154 = "CrossC2Beacon" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1155 = /CrossC2Kit\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1156 = /CrossC2Kit\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1157 = /CrossC2Kit\.git/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1158 = "CrossC2Kit_demo" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1159 = "crossc2kit_latest" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1160 = "CrossC2Kit_Loader" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1161 = "CrossC2Listener" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1162 = "CrossC2MemScriptEng" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1163 = "CrossC2Script" nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1164 = /CrossNet\.exe/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1165 = "CRTInjectAsSystem" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1166 = "CRTInjectElevated" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1167 = "CRTInjectWithoutPid" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1168 = /cs2modrewrite\.py/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1169 = /cs2nginx\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1170 = "CS-Avoid-killing" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1171 = "CS-BOFs/lsass" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1172 = "CSharpNamedPipeLoader" nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1173 = /csload\.net\/.{0,100}\/muma\./ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1174 = /csOnvps.{0,100}teamserver/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1175 = "CS-Remote-OPs-BOF" nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string1176 = /CSSG_load\.cna/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1177 = /cs\-token\-vault\.git/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1178 = "cube0x0/LdapSignCheck" nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string1179 = /custom_payload_generator\./ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1180 = "CustomKeyboardLayoutPersistence" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1181 = /CVE_20.{0,100}\.dll/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1182 = /cve\-20\.x64\.dll/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1183 = /cve\-20\.x86\.dll/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1184 = "DallasFR/Cobalt-Clip" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1185 = "darkr4y/geacon" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1186 = /dcsync\@protonmail\.com/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1187 = /dcsyncattack\(/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1188 = /dcsyncattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1189 = /dcsyncclient\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1190 = /dcsyncclient\.py/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1191 = "DeEpinGh0st/Erebus" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1192 = "DefaultBeaconApi" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1193 = /demo\-bof\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string1194 = /detect\-hooksx64\./ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1195 = "DisableAllWindowsSoftwareFirewalls" nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1196 = /disableeventvwr\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1197 = /dll\\reflective_dll\./ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1198 = "dll_hijack_hunter" nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1199 = "DLL_Imports_BOF" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1200 = "DLL_TO_HIJACK_WIN10" nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1201 = "DLL-Hijack-Search-Order-BOF" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1202 = "dllinject " nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1203 = "dns_beacon_beacon" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1204 = "dns_beacon_dns_idle" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1205 = "dns_beacon_dns_sleep" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1206 = "dns_beacon_dns_stager_prepend" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1207 = "dns_beacon_dns_stager_subhost" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1208 = "dns_beacon_dns_ttl" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1209 = "dns_beacon_get_A" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1210 = "dns_beacon_get_TXT" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1211 = "dns_beacon_maxdns" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1212 = "dns_beacon_ns_response" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1213 = "dns_beacon_put_metadata" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1214 = "dns_beacon_put_output" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1215 = /dns_redir\.sh\s/
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1216 = "dns_stager_prepend" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1217 = "'dns_stager_prepend'" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1218 = "'dns_stager_subhost'" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1219 = "dns-beacon " nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1220 = /dnspayload\.bin/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1221 = /do_attack\(/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string1222 = /Doge\-Loader.{0,100}xor\.go/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1223 = /douknowwhoami\?d/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1224 = "dr0op/CrossNet" nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1225 = /DReverseProxy\.git/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1226 = /DReverseServer\.go/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1227 = "drop_malleable_unknown_" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1228 = "drop_malleable_with_invalid_" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1229 = "drop_malleable_without_" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1230 = /dropper32\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1231 = /dropper64\.exe/ nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string1232 = "dtmsecurity/bof_helper" nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1233 = /Dumpert\.bin/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1234 = /Dumpert\.exe/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1235 = "Dumpert-Aggressor" nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1236 = /DumpShellcode\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1237 = /dumpXor\.exe\s/ nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1238 = "e42e1a7fcd23299df2ad4a3fe66e0f1df5a367ffe96015fd3a3b9c0a6dfcefdb" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1239 = /EasyPersistent\.cna/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1240 = "ebdf64076861a73d92416c6203d50dd25f4c991372f7d47e7146e29ab41a6892" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1241 = "elevate juicypotato " nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1242 = "elevate Printspoofer" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1243 = "elevate svc-exe " nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1244 = /ELFLoader\.c/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1245 = /ELFLoader\.h/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1246 = /ELFLoader\.out/ nocase ascii wide
        // Description: alternative to the Cobalt Strike Beacon
        // Reference: https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon
        $string1247 = "ElJaviLuki/CobaltStrike_OpenBeacon" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1248 = "empire AttackServers" nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1249 = "EncodeGroup/AggressiveProxy" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1250 = "EncodeGroup/UAC-SilentClean" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1251 = /encrypt\/encryptFile\.go/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1252 = /encrypt\/encryptUrl\.go/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1253 = /EncryptShellcode\(/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1254 = "engjibo/NetUser" nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string1255 = /EnumCLR\.exe/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1256 = /Erebus\/.{0,100}spacerunner/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1257 = "EspressoCake/PPLDump_BOF" nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1258 = /EventAggregation\.dll\.bak/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1259 = /eventspy\.cna/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1260 = /EventSub\-Aggressor\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1261 = /EventViewerUAC\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1262 = /EventViewerUAC\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1263 = /EventViewerUAC\.x64/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1264 = /EventViewerUAC\.x86/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1265 = "EventViewerUAC_BOF" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1266 = "eventvwr_elevator" nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1267 = /EVUAC\s.{0,100}\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1268 = "ewby/Mockingjay_BOF" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1269 = /example\-bof\.sln/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1270 = /execmethod.{0,100}PowerPick/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1271 = /execmethod.{0,100}PowerShell/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1272 = "execute_bof " nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1273 = /execute\-assembly\s.{0,100}\.exe\s/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1274 = "executepersistence" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1275 = "Export-PowerViewCSV" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1276 = "extract_reflective_loader" nocase ascii wide
        // Description: alternative to the Cobalt Strike Beacon
        // Reference: https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon
        $string1277 = "f65740929e9608e0590eee78f1ba20793d99163ac5f6dc1c8b8734b742c4da11" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1278 = "f8ce37975b71cc8f51fcb93e3e32ec81a9b5da5cead7dcb987d0a3127bde027c" nocase ascii wide
        // Description: alternative to the Cobalt Strike Beacon
        // Reference: https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon
        $string1279 = "ff732bedb8593016ffbe4925ce8fd87a74478b06391079413b70ee9e151826f2" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1280 = "Fiesta Exploit Kit" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1281 = /FileControler\/FileControler_x64\.dll/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1282 = /FileControler\/FileControler_x86\.dll/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1283 = /find_payload\(/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1284 = "findgpocomputeradmin" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1285 = "Find-GPOComputerAdmin" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1286 = "Find-InterestingDomainAcl" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1287 = "findinterestingdomainsharefile" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1288 = "Find-InterestingDomainShareFile" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1289 = "findlocaladminaccess" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1290 = "findlocaladminaccess" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1291 = "Find-LocalAdminAccess" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1292 = "Find-LocalAdminAccess" nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1293 = /FindModule\s.{0,100}\.dll/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1294 = "FindObjects-BOF" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1295 = "FindProcessTokenAndDuplicate" nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1296 = /FindProcHandle\s.{0,100}lsass/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1297 = "Firewall_Walker_BOF" nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1298 = "fishing_with_hollowing" nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1299 = /foreign_access\.cna/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1300 = /foreign_lsass\s.{0,100}\s/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1301 = /foreign_lsass\.c/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1302 = /foreign_lsass\.x64/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1303 = /foreign_lsass\.x86/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1304 = /\-\-format\-string\sziiiiizzzb\s.{0,100}\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1305 = "--format-string ziiiiizzzib " nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1306 = "fortra/No-Consolation" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1307 = "fucksetuptools" nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string1308 = /FuckThatPacker\./ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1309 = "FunnyWolf/pystinger" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1310 = "fw_walk disable" nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1311 = "G0ldenGunSec/GetWebDAVStatus" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1312 = /GadgetToJScript\.exe\s\-a\s/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1313 = "Gality369/CS-Loader" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1314 = "gather/keylogger" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1315 = /geacon.{0,100}\/cmd\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1316 = /genCrossC2\./ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1317 = "generate_beacon" nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1318 = /generate\-rotating\-beacon\./ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1319 = "GeorgePatsias/ScareCrow" nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string1320 = "get_BeaconHealthCheck_settings" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1321 = "get_dns_dnsidle" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1322 = "get_dns_sleep" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1323 = /get_password_policy\.x64\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1324 = /get_password_policy\.x86\./ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1325 = "get_post_ex_pipename_list" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1326 = "get_post_ex_spawnto_x" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1327 = "get_process_inject_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1328 = "get_process_inject_bof_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1329 = "get_process_inject_execute" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1330 = "get_stage_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1331 = "get_stage_magic_mz_64" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1332 = "get_stage_magic_mz_86" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1333 = "get_stage_magic_pe" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1334 = "get_virtual_Hook_address" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1335 = "getAggressorClient" nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1336 = "Get-BeaconAPI" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1337 = "Get-CachedRDPConnection" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1338 = "getCrossC2Beacon" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1339 = "getCrossC2Site" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1340 = "getdomainspnticket" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1341 = "Get-DomainSPNTicket" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1342 = "getexploitablesystem" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1343 = "Get-ExploitableSystem" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1344 = "GetHijackableDllName" nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1345 = "GetNTLMChallengeBase64" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1346 = /GetShellcode\(/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1347 = /GetWebDAVStatus\.csproj/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1348 = /GetWebDAVStatus\.sln/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1349 = "GetWebDAVStatus_DotNet" nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1350 = /GetWebDAVStatus_x64\.o/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1351 = "getwmiregcachedrdpconnection" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1352 = "Get-WMIRegCachedRDPConnection" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1353 = "getwmireglastloggedon" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1354 = "Get-WMIRegLastLoggedOn" nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1355 = /gexplorer\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1356 = "GhostPack/Koh" nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1357 = /github.{0,100}\/MoveKit\.git/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1358 = /github\.com\/k8gege/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1359 = /github\.com\/rasta\-mouse\// nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1360 = /github\.com\/SpiderLabs\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1361 = "gloxec/CrossC2" nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1362 = /go_shellcode_encode\.py/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1363 = /go\-shellcode\.py/ nocase ascii wide
        // Description: generate shellcode
        // Reference: https://github.com/fcre1938/goShellCodeByPassVT
        $string1364 = "goShellCodeByPassVT" nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1365 = /hackbrowersdata\.cna/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1366 = "hack-browser-data/" nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1367 = /handlekatz\.x64\./ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1368 = /handlekatz_bof\./ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1369 = "Hangingsword/HouQing" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1370 = /Havoc\-UACBypass\.py/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1371 = "hd-launch-cmd " nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1372 = /headers\/exploit\.h/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1373 = /headers\/HandleKatz\.h/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1374 = "Henkru/cs-token-vault" nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1375 = /Hidden\.Desktop\.mp4/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1376 = /HiddenDesktop\s.{0,100}\s/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1377 = /HiddenDesktop\./ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1378 = /HiddenDesktop\.x64\.bin/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1379 = /HiddenDesktop\.x86\.bin/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1380 = /HiddenDesktop\.zip/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1381 = "hijack_hunter " nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1382 = "hijack_remote_thread" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1383 = /HiveJack\-Console\.exe/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string1384 = /hollow\s.{0,100}\.exe\s.{0,100}\.bin/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1385 = /hollower\.Hollow\(/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1386 = /houqingv1\.0\.zip/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1387 = /html\/js\/beacons\.js/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1388 = /http.{0,100}\/zha0gongz1/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1389 = /http.{0,100}\:3200\/manjusaka/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1390 = /http.{0,100}\:801\/bq1iFEP2/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1391 = /http\:\/\/127\.0\.0\.1\:8000\/1\.jpg/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1392 = "http_stager_client_header" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1393 = "http_stager_server_append" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1394 = "http_stager_server_header" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1395 = "http_stager_server_prepend" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1396 = "http_stager_uri_x64" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1397 = "http_stager_uri_x86" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1398 = /http1\.x64\.bin/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1399 = /http1\.x64\.dll/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1400 = /httpattack\.py/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1401 = /httppayload\.bin/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1402 = "http-redwarden" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1403 = /httprelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1404 = /httprelayserver\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1405 = "'http-stager'" nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1406 = /HVNC\sServer\.exe/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1407 = /HVNC\\\sServer/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string1408 = "IcebreakerSecurity/DelegationBOF" nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1409 = "IcebreakerSecurity/PersistBOF" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1410 = "icyguider/UAC-BOF-Bonanza" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1411 = /imapattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1412 = /imaprelayclient\.py/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1413 = /impacket\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1414 = "ImpersonateLocalService" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1415 = /import\spe\.OBJExecutable/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1416 = /include\sbeacon\.h/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1417 = /include\sinjection\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1418 = "inject-amsiBypass " nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1419 = /inject\-amsiBypass\./ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1420 = "inject-assembly " nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1421 = /inject\-assembly\.cna/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1422 = /injectassembly\.x64\.bin/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1423 = /injectassembly\.x64\.o/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1424 = "injectEtwBypass" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1425 = "InjectShellcode" nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1426 = "inline-execute " nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1427 = /inline\-execute.{0,100}whereami\.x64/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1428 = "InlineExecute-Assembly" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string1429 = /InlineWhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string1430 = "InlineWhispers2" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1431 = "install impacket" nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1432 = "InvokeBloodHound" nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1433 = "Invoke-Bof " nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1434 = /Invoke\-Bof\.ps1/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1435 = "invokechecklocaladminaccess" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1436 = "Invoke-CheckLocalAdminAccess" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1437 = "invokeenumeratelocaladmin" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1438 = "Invoke-EnumerateLocalAdmin" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1439 = /Invoke\-EnvBypass\./ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1440 = "Invoke-EventVwrBypass" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1441 = "invokefilefinder" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1442 = "Invoke-FileFinder" nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string1443 = "Invoke-HostEnum -" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1444 = "invokekerberoast" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1445 = "Invoke-Kerberoast" nocase ascii wide
        // Description: powershell function used with cobaltstrike to kill parent process
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1446 = "Invoke-ParentalKilling" nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1447 = "Invoke-Phant0m" nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1448 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1449 = "invokeprocesshunter" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1450 = "Invoke-ProcessHunter" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1451 = "invokereverttoself" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1452 = "Invoke-RevertToSelf" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1453 = "invokesharefinder" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1454 = "Invoke-ShareFinder" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1455 = "invokestealthuserhunter" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1456 = "Invoke-StealthUserHunter" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1457 = "invokeuserhunter" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1458 = "Invoke-UserHunter" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1459 = "Invoke-WScriptBypassUAC" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string1460 = /Invoking\sCreateSvcRpc\s\(by\s\@x86matthew\)/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1461 = "jas502n/bypassAV" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1462 = /java\s\-jar\sBeaconTool\.jar/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1463 = /java\s\-jar\sBeaconTool\.jar/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1464 = "Job killed and console drained" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1465 = /jquery\-c2\..{0,100}\.profile/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1466 = "jump psexec_psh" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1467 = "jump psexec64" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1468 = "jump winrm " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1469 = "jump winrm" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1470 = "jump-exec scshell" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1471 = /K8_CS_.{0,100}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1472 = /k8gege\.org\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1473 = "k8gege/Ladon" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1474 = /K8Ladon\.sln/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1475 = /KaliLadon\./ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1476 = /KBDPAYLOAD\.dll/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1477 = /kdstab\s.{0,100}\s\/CHECK/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1478 = /kdstab\s.{0,100}\s\/CLOSE/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1479 = /kdstab\s.{0,100}\s\/DRIVER/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1480 = /kdstab\s.{0,100}\s\/KILL/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1481 = /kdstab\s.{0,100}\s\/LIST/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1482 = /kdstab\s.{0,100}\s\/NAME/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1483 = /kdstab\s.{0,100}\s\/PID/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1484 = /kdstab\s.{0,100}\s\/SERVICE/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1485 = /kdstab\s.{0,100}\s\/STRIP/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1486 = /kdstab\s.{0,100}\s\/UNLOAD/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1487 = /kdstab\.cna/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1488 = /kerberoasting\.x64/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1489 = /Kerberos\sabuse\s\(kerbeus\sBOF\)/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1490 = /kerberos.{0,100}\.kirbi/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1491 = /Kerbeus\s.{0,100}\sby\sRalfHacker/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1492 = /kerbeus_cs\.cna/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1493 = /kerbeus_havoc\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1494 = "Kerbeus-BOF-main" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1495 = /kernelcallbacktable\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1496 = /kernelcallbacktable\.x64/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1497 = /kernelcallbacktable\.x86/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1498 = /kernelcallbacktable\.x86/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1499 = /KernelMii\.cna/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1500 = /KernelMii\.x64\.exe/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1501 = /KernelMii\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1502 = /KernelMii\.x86\.exe/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1503 = /KernelMii\.x86\.o/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1504 = "killdefender check" nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1505 = "killdefender kill" nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1506 = /KillDefender\.x64/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1507 = /KillDefender\.x64\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1508 = "killdefender_bof" nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1509 = "KillDefender_BOF" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1510 = /kirbi\.tickets/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1511 = "koh filter add SID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1512 = "koh filter list" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1513 = "koh filter remove SID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1514 = "koh filter reset" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1515 = "koh groups LUID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1516 = "koh impersonate LUID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1517 = "koh release all" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1518 = "koh release LUID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1519 = /Koh\.exe\scapture/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1520 = /Koh\.exe\slist/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1521 = /Koh\.exe\smonitor/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1522 = "krb_asktgs /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1523 = "krb_asktgt /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1524 = "krb_asreproasting" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1525 = "krb_changepw /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1526 = "krb_cross_s4u /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1527 = "krb_describe /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1528 = "krb_dump /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1529 = "krb_hash /password" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1530 = "krb_klist /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1531 = "krb_ptt /ticket:" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1532 = "krb_purge /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1533 = "krb_renew /ticket:" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1534 = "krb_s4u /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1535 = "krb_tgtdeleg /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1536 = /krb_tgtdeleg\(.{0,100}\)/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1537 = "krb_triage /" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1538 = /krb5\/kerberosv5\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1539 = "krbasktgt /" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1540 = /krbcredccache\.py/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string1541 = "kyleavery/AceLdr" nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1542 = "kyleavery/inject-assembly" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1543 = /Ladon\s.{0,100}\sAllScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1544 = /Ladon\s.{0,100}\sCiscoScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1545 = /Ladon\s.{0,100}\sOnlineIP/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1546 = /Ladon\s.{0,100}\sOnlinePC/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1547 = /Ladon\s.{0,100}\sOsScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1548 = /Ladon\s.{0,100}\sOxidScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1549 = /Ladon\s.{0,100}\.txt\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1550 = /Ladon\s.{0,100}DeBase64/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1551 = /Ladon\s.{0,100}FtpScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1552 = /Ladon\s.{0,100}LdapScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1553 = /Ladon\s.{0,100}SMBGhost/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1554 = /Ladon\s.{0,100}SmbHashScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1555 = /Ladon\s.{0,100}SmbScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1556 = /Ladon\s.{0,100}SshScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1557 = /Ladon\s.{0,100}TomcatScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1558 = /Ladon\s.{0,100}VncScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1559 = /Ladon\s.{0,100}WebScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1560 = /Ladon\s.{0,100}WinrmScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1561 = /Ladon\s.{0,100}WmiHashScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1562 = /Ladon\s.{0,100}WmiScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1563 = "Ladon ActiveAdmin" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1564 = "Ladon ActiveGuest" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1565 = "Ladon AdiDnsDump " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1566 = "Ladon at c:" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1567 = "Ladon AtExec" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1568 = "Ladon AutoRun" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1569 = "Ladon BadPotato" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1570 = "Ladon BypassUAC" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1571 = "Ladon CheckDoor" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1572 = "Ladon Clslog" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1573 = "Ladon CmdDll " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1574 = "Ladon cmdline" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1575 = "Ladon CVE-" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1576 = "Ladon DirList" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1577 = "Ladon DraytekExp" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1578 = "Ladon DumpLsass" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1579 = "Ladon EnableDotNet" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1580 = "Ladon EnumProcess" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1581 = "Ladon EnumShare" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1582 = "Ladon Exploit" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1583 = "Ladon FindIP " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1584 = "Ladon FirefoxCookie" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1585 = "Ladon FirefoxHistory" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1586 = "Ladon FirefoxPwd" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1587 = "Ladon ForExec " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1588 = "Ladon FtpDownLoad " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1589 = "Ladon FtpServer " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1590 = "Ladon GetDomainIP" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1591 = "Ladon gethtml " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1592 = "Ladon GetPipe" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1593 = "Ladon GetSystem" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1594 = "Ladon IISdoor" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1595 = "Ladon IISpwd" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1596 = "Ladon MssqlCmd " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1597 = "Ladon netsh " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1598 = "Ladon noping " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1599 = "Ladon Open3389" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1600 = "Ladon PowerCat " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1601 = "Ladon PrintNightmare" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1602 = "Ladon psexec" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1603 = "Ladon QueryAdmin" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1604 = "Ladon RdpHijack" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1605 = "Ladon ReadFile " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1606 = "Ladon RegAuto" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1607 = "Ladon ReverseHttps" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1608 = "Ladon ReverseTcp " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1609 = "Ladon RevShell-" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1610 = "Ladon Runas" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1611 = "Ladon RunPS " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1612 = "Ladon sc " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1613 = "Ladon SetSignAuth" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1614 = "Ladon SmbExec " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1615 = "Ladon Sniffer" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1616 = "Ladon SshExec " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1617 = "Ladon SweetPotato" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1618 = "Ladon TcpServer " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1619 = "Ladon UdpServer" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1620 = "Ladon WebShell" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1621 = "Ladon whoami" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1622 = "Ladon WifiPwd" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1623 = "Ladon wmiexec" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1624 = "Ladon WmiExec2 " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1625 = "Ladon XshellPwd" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1626 = "Ladon ZeroLogon" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1627 = "Ladon40 BypassUAC" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1628 = /Ladon911.{0,100}\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1629 = /Ladon911\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1630 = /Ladon911_.{0,100}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1631 = /LadonExp\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1632 = /LadonGUI\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1633 = /LadonLib\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1634 = /LadonStudy\.exe/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1635 = /lastpass\.x86/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1636 = /lastpass\/process_lp_files\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1637 = /ldap_shell\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1638 = /ldapattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1639 = /ldaprelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1640 = /LdapSignCheck\.exe/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1641 = /LdapSignCheck\.Natives/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1642 = /LdapSignCheck\.sln/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1643 = /ldapsigncheck\.x64\./ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1644 = /ldapsigncheck\.x86\./ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1645 = /LetMeOutSharp\./ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1646 = "libs/bofalloc" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1647 = "libs/bofentry" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1648 = "libs/bofhelper" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1649 = /LiquidSnake\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1650 = "llsrpc_##" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1651 = "load aggressor script" nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string1652 = /load_sc\.exe\s.{0,100}\.bin/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1653 = "Load-BeaconParameters" nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1654 = /Load\-Bof\(/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1655 = /loader\/loader\/loader\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1656 = /localS4U2Proxy\.tickets/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1657 = "logToBeaconLog" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1658 = "lsarpc_##" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1659 = "Magnitude Exploit Kit" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1660 = /main_air_service\-probes\.go/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1661 = /main_pro_service\-probes\.go/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1662 = /makebof\.bat/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string1663 = "Malleable C2 Files" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1664 = "Malleable PE/Stage" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1665 = /malleable_redirector\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1666 = "malleable_redirector_hidden_api_endpoint" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1667 = "Malleable-C2-Profiles" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1668 = "Malleable-C2-Randomizer" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1669 = "Malleable-C2-Randomizer" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1670 = "malleable-redirector-config" nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string1671 = "mandllinject " nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1672 = "mdsecactivebreach/CACTUSTORCH" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1673 = "med0x2e/SigFlip" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1674 = /memreader\s.{0,100}access_token/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1675 = /MemReader_BoF\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1676 = /meterpreter\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1677 = /metsrv\.dll/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1678 = "mgeeky/RedWarden" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1679 = /mimipenguin\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1680 = /mimipenguin\.so/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1681 = /mimipenguin_x32\.so/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1682 = "minidump_add_memory_block" nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1683 = "minidump_add_memory64_block" nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1684 = "miscbackdoorlnkhelp" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1685 = /Mockingjay_BOF\.sln/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1686 = "Mockingjay_BOF-main" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1687 = "mojo_##" nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1688 = "moonD4rk/HackBrowserData" nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1689 = /MoveKit\-master\.zip/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1690 = /move\-msbuild\s.{0,100}\shttp\smove\.csproj/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1691 = /move\-pre\-custom\-file\s.{0,100}\.exe\s/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string1692 = "msfvemonpayload" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1693 = /mssqlattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1694 = /mssqlrelayclient\.py/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1695 = "my_dump_my_pe" nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1696 = /needle_sift\.x64/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1697 = /needlesift\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1698 = "netero1010/Quser-BOF" nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1699 = "netero1010/ServiceMove-BOF" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1700 = "netlogon_##" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1701 = "netuser_enum" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1702 = "netview_enum" nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1703 = /NoApiUser\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1704 = "noconsolation /tmp/" nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1705 = /noconsolation\s\-\-local\s.{0,100}cmd\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1706 = /noconsolation\s\-\-local\s.{0,100}powershell\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1707 = /No\-Consolation\.cna/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1708 = /NoConsolation\.x64\.o/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1709 = /NoConsolation\.x86\.o/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1710 = "No-Consolation-main" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1711 = /normal\/randomized\.profile/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1712 = /ntcreatethread\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1713 = /ntcreatethread\.x86/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1714 = /oab\-parse\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1715 = "obscuritylabs/ase:latest" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1716 = "obscuritylabs/RAI/" nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1717 = "Octoberfest7/KDStab" nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1718 = "OG-Sadpanda/SharpCat" nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string1719 = "OG-Sadpanda/SharpSword" nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string1720 = "OG-Sadpanda/SharpZippo" nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1721 = /On_Demand_C2\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1722 = /On\-Demand_C2_BOF\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1723 = /OnDemandC2Class\.cs/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1724 = "openBeaconBrowser" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1725 = "openBeaconBrowser" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1726 = "openBeaconConsole" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1727 = "openBeaconConsole" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1728 = "openBypassUACDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1729 = "openBypassUACDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1730 = "openGoldenTicketDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1731 = "openKeystrokeBrowser" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1732 = "openPayloadGenerator" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1733 = "openPayloadGeneratorDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1734 = "openPayloadHelper" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1735 = "openPortScanner" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1736 = "openPortScanner" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1737 = "openSpearPhishDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1738 = "openWindowsExecutableStage" nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string1739 = "optiv/Registry-Recon" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1740 = "optiv/ScareCrow" nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1741 = /Outflank\-Dumpert\./ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1742 = "outflanknl/Recon-AD" nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string1743 = "outflanknl/Spray-AD" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string1744 = "outflanknl/WdToggle" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1745 = "Outflank-Recon-AD" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1746 = /output\/html\/data\/beacons\.json/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1747 = "output/payloads/" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1748 = /package\scom\.blackh4t/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1749 = /parse\sthe\s\.beacon_keys\sto\sRSA\sprivate\skey\sand\spublic\skey\sin\spem\sformat/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1750 = "parse_aggressor_properties" nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1751 = "parse_shellcode" nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1752 = "patchAmsiOpenSession" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1753 = "payload_bootstrap_hint" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1754 = "payload_local" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1755 = /payload_scripts\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1756 = "payload_scripts/sleepmask" nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1757 = /payload_section\.cpp/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1758 = /payload_section\.hpp/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1759 = /payloadgenerator\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1760 = "Perform AS-REP roasting" nocase ascii wide
        // Description: cobaltstrike plugin (This reads an ADFIND dump and CSVs it) used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1761 = /perl\sadcsv\.pl\s/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1762 = /PersistBOF\.cna/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1763 = /PersistenceBOF\.c/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1764 = /PersistenceBOF\.exe/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1765 = /persist\-ice\-junction\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1766 = /persist\-ice\-monitor\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1767 = /persist\-ice\-shortcut\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1768 = /persist\-ice\-time\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1769 = /persist\-ice\-xll\.o/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1770 = "Phant0m_cobaltstrike" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1771 = "'pipename_stager'" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1772 = "Pitty Tiger RAT" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1773 = /\-pk8gege\.org/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1774 = /pkexec64\.tar\.gz/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1775 = /plug_getpass_nps\.dll/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1776 = /plug_katz_nps\.exe/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1777 = /plug_qvte_nps\.exe/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1778 = "PoolParty attack completed successfully" nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1779 = "PoolPartyBof " nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1780 = /PoolPartyBof\s.{0,100}\sHTTPSLocal/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1781 = /PoolPartyBof\.cna/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1782 = "PoolPartyBof-main" nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1783 = "PortBender backdoor" nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1784 = "PortBender redirect" nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1785 = /PortBender\.cna/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1786 = /PortBender\.cpp/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1787 = /portbender\.dll/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1788 = /PortBender\.exe/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1789 = /PortBender\.h/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1790 = /PortBender\.sln/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1791 = /PortBender\.zip/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1792 = /portscan_result\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1793 = "portscan386 " nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1794 = "portscan64 " nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1795 = "post_ex_amsi_disable" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1796 = "post_ex_keylogger" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1797 = "post_ex_obfuscate" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1798 = "Post_EX_Process_Name" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1799 = "post_ex_smartinject" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1800 = "post_ex_spawnto_x64" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1801 = "post_ex_spawnto_x86" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1802 = "powershell_encode_oneliner" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1803 = "powershell_encode_oneliner" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1804 = "powershell_encode_stager" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1805 = "powershell_encode_stager" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1806 = /powershell\-import\s.{0,100}\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1807 = "PowerView3-Aggressor" nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1808 = /ppenum\.c/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1809 = /ppenum\.exe/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1810 = /ppenum\.x64\./ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1811 = /ppenum\.x86\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1812 = /ppl_dump\.x64/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1813 = "ppldump " nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1814 = /PPLDump_BOF\./ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1815 = /pplfault\.cna/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1816 = "PPLFaultDumpBOF" nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1817 = /PPLFaultPayload\.dll/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1818 = "PPLFaultTemp" nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1819 = /praetorian\.antihacker/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1820 = "praetorian-inc/PortBender" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1821 = "prepareResponseForHiddenAPICall" nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1822 = "PrintSpoofer-" nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1823 = /PrintSpoofer\./ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1824 = /process_imports\.cna/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1825 = /process_imports\.x64/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1826 = /process_imports_api\s.{0,100}\.exe/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1827 = "process_inject_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1828 = "process_inject_bof_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1829 = "process_inject_bof_reuse_memory" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1830 = "process_inject_execute" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1831 = "process_inject_min_alloc" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1832 = "process_inject_startrwx" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1833 = "Process_Inject_Struct" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1834 = "process_inject_transform_x" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1835 = "process_inject_userwx" nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1836 = "process_protection_enum " nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1837 = /process_protection_enum.{0,100}\.dmp/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1838 = /process_protection_enum\./ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1839 = /Process_Protection_Level_BOF\./ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1840 = "Process_Protection_Level_BOF/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1841 = /ProcessDestroy\.x64/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1842 = /ProcessDestroy\.x64\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1843 = /ProcessDestroy\.x86/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1844 = /ProcessDestroy\.x86\./ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1845 = "process-inject " nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1846 = "processinject_min_alloc" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1847 = /ProgIDsUACBypass\./ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1848 = "Proxy Shellcode Handler" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1849 = /proxychains.{0,100}scshell/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1850 = "proxyshellcodeurl" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1851 = /PSconfusion\.py/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1852 = "PSEXEC_PSH " nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/pureqh/bypassAV
        $string1853 = "pureqh/bypassAV" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1854 = "pwn1sher/CS-BOFs" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1855 = /pycobalt\./ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1856 = "pycobalt/aggressor" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1857 = "pycobalt_debug_on" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1858 = "pycobalt_path" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1859 = "pycobalt_python" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1860 = "pycobalt_timeout" nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1861 = "pyMalleableC2" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1862 = "pystinger_for_darkshadow" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1863 = "python scshell" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1864 = /python2\?\?\/generator\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1865 = /python2\?\?\/PyLoader\.py/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1866 = "python3 scshell" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1867 = /python3\?\?\/generator\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1868 = /python3\?\?\/PyLoader\.py/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1869 = "QUAPCInjectAsSystem" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1870 = "QUAPCInjectElevated" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1871 = "QUAPCInjectFakecmd" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1872 = "QUAPCInjectFakecmd" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1873 = "QUAPCInjectWithoutPid" nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1874 = /quser\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1875 = /quser\.x86\.o/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1876 = "QXh4OEF4eDhBeHg4QXh4OA==" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1877 = "RAI/ase_docker" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1878 = /rai\-attack\-servers\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1879 = "rai-redirector-dns" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1880 = "rai-redirector-http" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1881 = "RalfHacker/Kerbeus-BOF" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1882 = "random_c2_profile" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1883 = /random_c2profile\./ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1884 = /random_user_agent\.params/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1885 = /random_user_agent\.user_agent/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1886 = "rasta-mouse/PPEnum" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1887 = "rasta-mouse/TikiTorch" nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1888 = /rdi_net_user\.cpp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1889 = /rdphijack\.x64/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1890 = /rdphijack\.x86/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1891 = "RDPHijack-BOF" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1892 = /RdpThief\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1893 = "read_cs_teamserver" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1894 = /Recon\-AD\-.{0,100}\.dll/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1895 = /Recon\-AD\-.{0,100}\.sln/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1896 = /Recon\-AD\-.{0,100}\.vcxproj/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1897 = "Recon-AD-AllLocalGroups" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1898 = "Recon-AD-Domain" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1899 = "Recon-AD-LocalGroups" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1900 = "Recon-AD-SPNs" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1901 = /Recon\-AD\-Users\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1902 = "redelk_backend_name_c2" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1903 = "redelk_backend_name_decoy" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1904 = /Red\-Team\-Infrastructure\-Wiki\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1905 = /RedWarden\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1906 = /RedWarden\.test/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1907 = /redwarden_access\.log/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1908 = /redwarden_redirector\.log/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1909 = /reflective_dll\.dll/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1910 = /reflective_dll\.x64\.dll/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1911 = /ReflectiveDll\.x64\.dll/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1912 = /ReflectiveDll\.x86\.dll/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1913 = "Reflective-HackBrowserData" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1914 = /Remote\/lastpass\/lastpass\.x86\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1915 = "Remote/setuserpass/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1916 = "Remote/shspawnas" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1917 = "Remote/suspendresume/" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1918 = /remote\-exec\s.{0,100}jump\s/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1919 = /remotereg\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1920 = "replace_key_iv_shellcode" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1921 = "RiccardoAncarani/BOFs" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1922 = "RiccardoAncarani/LiquidSnake" nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string1923 = "RiccardoAncarani/TaskShell" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1924 = "rkervella/CarbonMonoxide" nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1925 = "rookuu/BOFs/" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1926 = /rpcattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1927 = /rpcrelayclient\.py/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1928 = "rsmudge/ElevateKit" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1929 = "runasadmin uac-cmstplua" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1930 = "runasadmin uac-token-duplication" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1931 = /RunOF\.exe\s\-/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1932 = /RunOF\.Internals/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1933 = /rustbof\.cna/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1934 = "rvrsh3ll/BOF_Collection" nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1935 = "rxwx/cs-rdll-ipc-example" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1936 = /s4u\.x64\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1937 = /s4u\.x64\.o/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1938 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1939 = /SamAdduser\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1940 = "samr_##" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1941 = /ScareCrow.{0,100}\s\-encryptionmode\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1942 = /ScareCrow.{0,100}\s\-Evasion/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1943 = /ScareCrow.{0,100}\s\-Exec/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1944 = /ScareCrow.{0,100}\s\-injection/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1945 = /ScareCrow.{0,100}\s\-Loader\s.{0,100}\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1946 = /ScareCrow.{0,100}\s\-noamsi/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1947 = /ScareCrow.{0,100}\s\-noetw/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1948 = /ScareCrow.{0,100}\s\-obfu/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1949 = /ScareCrow.{0,100}_darwin_amd64/
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1950 = /ScareCrow.{0,100}_windows_amd64\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1951 = /ScareCrow.{0,100}KnownDLL/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1952 = /ScareCrow.{0,100}ProcessInjection/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1953 = /ScareCrow\.cna/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1954 = "ScareCrow/Cryptor" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1955 = "ScareCrow/limelighter" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1956 = "ScareCrow/Loader" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1957 = "ScareCrow/Utils" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1958 = /schshell\.cna/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1959 = "schtask_callback" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1960 = "schtasks_elevator" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1961 = "schtasks_exploit " nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1962 = /ScRunBase32\.exe/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1963 = /ScRunBase32\.py/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1964 = /ScRunBase64\.exe/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1965 = /ScRunBase64\.py/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1966 = /scshell.{0,100}XblAuthManager/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1967 = /SCShell\.exe/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1968 = /scshell\.py/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1969 = /scshellbof\.c/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1970 = /scshellbof\.o/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1971 = "scshellbofx64" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1972 = "searchsploit_rc" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1973 = /Seatbelt\.exe/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1974 = "sec-inject " nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1975 = /secinject\.cna/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1976 = /secinject\.git/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1977 = /secinject\.x64/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1978 = /secinject\.x86/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1979 = "secinject/src" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1980 = /secretsdump\..{0,100}\.pyc/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1981 = /secretsdump\.py/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1982 = "sec-shinject " nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1983 = /self_delete\.x64\.o/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1984 = "Self_Deletion_BOF" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1985 = "send_shellcode_via_pipe" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1986 = "send_shellcode_via_pipe" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1987 = /serverscan\.linux\.elf/
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1988 = /serverscan\.linux\.so/
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1989 = /serverScan\.win\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1990 = /serverscan_386\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1991 = /ServerScan_Air_.{0,100}\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1992 = /ServerScan_Air_.{0,100}_amd64/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1993 = /ServerScan_Air_.{0,100}_i386/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1994 = /serverscan_air\-probes\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1995 = /serverscan_amd64\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1996 = /ServerScan_Pro_.{0,100}\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1997 = /ServerScan_Pro_.{0,100}_amd64/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1998 = /ServerScan_Pro_.{0,100}_i386/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1999 = "serverscan64 " nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string2000 = /serverscan64\s.{0,100}tcp/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string2001 = "serverscan86 " nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string2002 = /servicemove.{0,100}hid\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2003 = "set hosts_stage" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2004 = "set keylogger" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2005 = "set obfuscate " nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2006 = "set pipename " nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2007 = "set smartinject" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2008 = "set userwx" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2009 = "setc_webshell" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string2010 = "setLoaderFlagZero" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2011 = /setthreadcontext\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2012 = /setthreadcontext\.x86/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string2013 = "setup_obfuscate_xor_key" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2014 = "setup_reflective_loader" nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string2015 = "seventeenman/CallBackDump" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string2016 = /ShadowUser\/scvhost\.exe/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string2017 = /SharpCalendar\.exe/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string2018 = /SharpCat\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2019 = /sharpcompile.{0,100}\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2020 = "sharpCompileHandler" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2021 = "SharpCompileServer" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2022 = /SharpCompileServer\.exe/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string2023 = /SharpCradle.{0,100}logonpasswords/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string2024 = /SharpCradle\.exe/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string2025 = "SharpEventLoader" nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string2026 = "SharpEventPersist" nocase ascii wide
        // Description: Read Excel Spreadsheets (XLS/XLSX) using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpExcelibur
        $string2027 = "SharpExcelibur" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2028 = "sharp-exec " nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2029 = "sharp-fexec " nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2030 = /SharpGen\.dll/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2031 = /sharpgen\.enable_cache/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2032 = /sharpgen\.py/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2033 = /sharpgen\.set_location/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string2034 = "Sharp-HackBrowserData" nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2035 = /SharpHound\.cna/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2036 = /SharpHound\.exe/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2037 = /SharpHound\.ps1/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2038 = /Sharphound2\./ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2039 = "Sharphound-Aggressor" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2040 = "SharpSCShell" nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string2041 = "SharpSploitConsole_x" nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string2042 = /SharpStay\.exe/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string2043 = /SharpSword\.exe/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2044 = "SharpZeroLogon" nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string2045 = /SharpZippo\.exe/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string2046 = /shell\.exe\s\-s\spayload\.txt/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string2047 = /Shellcode_encryption\.exe/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string2048 = /shellcode_generator\./ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string2049 = /shellcode_generator_help\.html/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string2050 = /ShellCode_Loader\.py/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2051 = /shellcode20\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2052 = /shellcode30\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2053 = /shellcode35\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2054 = /shellcode40\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2055 = "shspawn x64 " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2056 = "shspawn x86 " nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2057 = /SigFlip\.exe\s\-/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2058 = /SigFlip\.WinTrustData/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2059 = /SigInject\s.{0,100}\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2060 = /Sigloader\s.{0,100}\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2061 = /SigLoader\/sigloader\.c/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2062 = /sigwhatever\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string2063 = "Silent Lsass Dump" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string2064 = "SilentCleanupWinDirBOF" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string2065 = "silentLsassDump" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2066 = "-Situational-Awareness-BOF" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2067 = /sleep_python_bridge\.sleepy/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2068 = /sleep_python_bridge\.striker/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2069 = /sleepmask\.x64\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2070 = /sleepmask\.x86\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2071 = /sleepmask_pivot\.x64\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2072 = /sleepmask_pivot\.x86\.o/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2073 = "smb_pipename_stager" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2074 = /smbattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2075 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2076 = /smbrelayserver\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2077 = /smtprelayclient\.py/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2078 = "socky whoami" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2079 = /SourcePoint.{0,100}Loader\.go/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2080 = /source\-teamserver\.sh/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string2081 = "spawn/runshellcode" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2082 = /SpawnTheThing\(/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2083 = /spawnto\s.{0,100}\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2084 = "'spawnto_x64'" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2085 = "'spawnto_x86'" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2086 = "spoolss_##" nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2087 = "spoolsystem inject" nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2088 = "spoolsystem spawn" nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2089 = /spoolsystem\.cna/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2090 = /SpoolTrigger\.x64\.dl/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2091 = /SpoolTrigger\.x64\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2092 = /SpoolTrigger\.x86\.dl/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2093 = /SpoolTrigger\.x86\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2094 = /SpoolTrigger\\SpoolTrigger\./ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2095 = "Spray-AD " nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2096 = /Spray\-AD\.cna/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2097 = /Spray\-AD\.dll/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2098 = /Spray\-AD\.exe/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2099 = /Spray\-AD\.sln/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2100 = /Spray\-AD\\Spray\-AD/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2101 = "src/Remote/chromeKey/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2102 = "src/Remote/lastpass/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2103 = "src/Remote/sc_config/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2104 = "src/Remote/sc_create/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2105 = "src/Remote/sc_delete/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2106 = "src/Remote/sc_start/" nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2107 = "Src/Spray-AD" nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2108 = /src\/zerologon\.c/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string2109 = /src\\unhook\.c/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2110 = "srvsvc_##" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string2111 = "SspiUacBypass" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string2112 = "SspiUacBypassBOF" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2113 = /stage\.obfuscate/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2114 = "stage_smartinject" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2115 = "stage_transform_x64_prepend" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2116 = "stage_transform_x64_strrep1" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2117 = "stage_transform_x86_prepend" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2118 = "stage_transform_x86_strrep1" nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string2119 = "stageless payload" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2120 = "stager_bind_pipe" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2121 = "stager_bind_pipe" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2122 = "stager_bind_tcp" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2123 = "stager_bind_tcp" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2124 = "start stinger " nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string2125 = "Starting PoolParty attack against process id:" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2126 = /StartProcessFake\(/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2127 = "static_syscalls_apc_spawn " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2128 = "static_syscalls_apc_spawn" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2129 = "static_syscalls_dump" nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2130 = /StayKit\.cna/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2131 = /StayKit\.exe/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2132 = /StayKit\.git/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2133 = /steal_token\(/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2134 = "steal_token_access_mask" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2135 = "stinger_client -" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2136 = /stinger_client\.py/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2137 = /stinger_server\.exe/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2138 = /strip_bof\.ps1/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2139 = "strip-bof -Path " nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2140 = /sudo\s\.\/teamserver\s/
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2141 = /suspendresume\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2142 = /suspendresume\.x86\./ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2143 = "SW2_GetSyscallNumber" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2144 = "SW2_HashSyscall" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2145 = "SW2_PopulateSyscallList" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2146 = "SW2_RVA2VA" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2147 = /SwampThing\.exe/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2148 = /SweetPotato\.cna/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2149 = /SweetPotato\.csproj/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2150 = /SweetPotato\.exe/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2151 = /SweetPotato\.ImpersonationToken/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2152 = /SweetPotato\.sln/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2153 = "syscall_disable_priv " nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2154 = "syscall_enable_priv " nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2155 = /syscalls\.asm/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2156 = /syscalls_dump\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2157 = "syscalls_inject " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2158 = /syscalls_inject\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2159 = "syscalls_shinject " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2160 = "syscalls_shspawn " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2161 = "syscalls_spawn " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2162 = /syscalls_spawn\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2163 = /syscallsapcspawn\.x64/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2164 = /syscalls\-asm\.h/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2165 = /syscallsdump\.x64/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2166 = /syscallsinject\.x64/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2167 = /syscallsspawn\.x64/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2168 = /systemctl\senable\steamserver\.service/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2169 = /systemctl\sstart\steamserver\.service/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2170 = /systemctl\sstatus\steamserver\.service/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2171 = /SysWhispers\.git\s/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2172 = /syswhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2173 = /syswhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2174 = "SysWhispers2" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2175 = /TailorScan\.exe\s/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2176 = "TailorScan_darwin"
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2177 = "TailorScan_freebsd" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2178 = "TailorScan_linux_"
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2179 = "TailorScan_netbsd_" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2180 = "TailorScan_openbsd_" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2181 = /TailorScan_windows_.{0,100}\.exe/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2182 = /TaskShell\.exe\s.{0,100}\s\-b\s.{0,100}\.exe/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2183 = /TaskShell\.exe\s.{0,100}\s\-s\s.{0,100}SYSTEM/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2184 = /teamserver\s.{0,100}\sc2\-profiles\// nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string2185 = /teamserver.{0,100}\sno_evasion\.profile/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string2186 = /TeamServer\.prop/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string2187 = /Temp\\dumpert/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string2188 = /test_invoke_bof\.x64\.o/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2189 = "tgtdelegation " nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2190 = /tgtdelegation\.cna/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2191 = /tgtdelegation\.x64/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2192 = /tgtdelegation\.x86/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2193 = /tgtParse\.py\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2194 = "third_party/SharpGen" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2195 = /third\-party.{0,100}winvnc.{0,100}\.dll/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2196 = /threatexpress.{0,100}malleable/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string2197 = "threatexpress/cs2modrewrite" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2198 = /ticketConverter\.py\s.{0,100}\.ccache\s/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string2199 = "tijme/kernel-mii" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2200 = /TikiLoader.{0,100}Hollower/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2201 = /TikiLoader\./ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2202 = /TikiLoader\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2203 = /TikiLoader\.dll/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2204 = /TikiLoader\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2205 = /TikiLoader\.Injector/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2206 = /TikiLoader\\TikiLoader/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2207 = /TikiSpawn\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2208 = /TikiSpawn\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2209 = /TikiSpawn\.ps1/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2210 = "TikiSpawnAs" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2211 = "TikiSpawnAsAdmin" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2212 = "TikiSpawnElevated" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2213 = "TikiSpawnWOppid" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2214 = "TikiSpawnWppid" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2215 = /TikiTorch\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2216 = /TikiVader\./ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2217 = "timwhitez/Doge-Loader" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2218 = /Tmprovider\.dll/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2219 = /toggle_privileges\.cna/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2220 = /toggle_privileges_bof\./ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2221 = "Toggle_Token_Privileges_BOF" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2222 = "ToggleWDigest" nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string2223 = "TokenStripBOF/src" nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2224 = "token-vault steal" nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2225 = /token\-vault\.cna/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2226 = /token\-vault\.x64\.o/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2227 = /token\-vault\.x86\.o/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string2228 = "trainr3kt/MemReader_BoF" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string2229 = "trainr3kt/Readfile_BoF" nocase ascii wide
        // Description: Collection of UAC Bypass Techniques Weaponized as BOFs
        // Reference: https://github.com/icyguider/UAC-BOF-Bonanza
        $string2230 = "TrustedPathDLLHijack" nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2231 = "TrustedPath-UACBypass-BOF" nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2232 = "Tycx2ry/SweetPotato" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2233 = "Tylous/SourcePoint" nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2234 = "UACBypass-BOF" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2235 = "uac-schtasks " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2236 = "uac-schtasks" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string2237 = "uac-silentcleanup" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2238 = "uac-token-duplication" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2239 = /uhttpsharp\./ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2240 = "uknowsec/TailorScan" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2241 = "UMJjAiNUUtvNww0lBj9tzWegwphuIn6hNP9eeIDfOrcHJ3nozYFPT-Jl7WsmbmjZnQXUesoJkcJkpdYEdqgQFE6QZgjWVsLSSDonL28DYDVJ" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2242 = "Un1k0d3r/SCShell" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string2243 = /ursnif_IcedID\.profile/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2244 = "Visual-Studio-BOF-template" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2245 = /vssenum\.x64\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2246 = /vssenum\.x86\./ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string2247 = "vysecurity/ANGRYPUPPY" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2248 = /wcfrelayserver\.py/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2249 = "wdigest!g_fParameter_UseLogonCredential" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2250 = "wdigest!g_IsCredGuardEnabled" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2251 = /whereami\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2252 = /whereami\.x64/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2253 = "WhoamiGetTokenInfo" nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2254 = /wifidump\.cna/ nocase ascii wide
        // Description: cobaltstrike default content strings
        // Reference: https://www.cobaltstrike.com/
        $string2255 = "windows/beacon_smb/" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string2256 = /windows\-exploit\-suggester\./ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2257 = "winrmdll " nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2258 = /winrmdll\./ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2259 = "Winsocky-main" nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string2260 = "WKL-Sec/HiddenDesktop" nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2261 = "WKL-Sec/Winsocky" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2262 = "wkssvc_##" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string2263 = /Wmi_Persistence\.ps1/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2264 = /wmi\-event\-lateral\-movement\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2265 = /WMI\-EventSub\.cpp/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2266 = /wmi\-lateral\-movement\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2267 = /WMI\-ProcessCreate\.cpp/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string2268 = "write_cs_teamserver" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2269 = "WriteAndExecuteShellcode" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string2270 = "WritePayloadDllTransacted" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2271 = "wscript_elevator" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string2272 = "wts_enum_remote_processes" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string2273 = "wumb0/rust_bof" nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string2274 = "xforcered/CredBandit" nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/xforcered/Detect-Hooks
        $string2275 = "xforcered/Detect-Hooks" nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2276 = /xor\.exe\s.{0,100}\.txt/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string2277 = "xor_payload" nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2278 = /xpipe\s\\\\/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2279 = /xpipe.{0,100}lsass/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2280 = /xpipe\.cna/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string2281 = /YDHCUI\/csload\.net/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string2282 = "YDHCUI/manjusaka" nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string2283 = "youcantpatchthis" nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2284 = /ysoserial\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2285 = "YwBhAGwAYwA=" nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2286 = /zerologon\.x64/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2287 = /zerologon\.x86/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2288 = "ZeroLogon-BOF" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2289 = "zha0gongz1" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2290 = "zha0gongz1/DesertFox" nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2291 = "ziiiiizzzb" nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2292 = "ziiiiizzzib" nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2293 = /\\\\demoagent_11/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2294 = /\\\\demoagent_22/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2295 = /\\\\DserNamePipe/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2296 = /\\\\f4c3/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2297 = /\\\\f53f/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2298 = /\\\\fullduplex_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2299 = /\\\\interprocess_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2300 = /\\\\mojo_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2301 = /\\\\msagent_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2302 = /\\\\MsFteWds/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2303 = /\\\\MSSE\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2304 = /\\\\mypipe\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2305 = /\\\\PGMessagePipe/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2306 = /\\\\postex_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2307 = /\\\\postex_ssh_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2308 = /\\\\SearchTextHarvester/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2309 = /\\\\UIA_PIPE/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2310 = /\\\\Winsock2\\CatalogChangeListener\-/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2311 = /\\Ladon\s.{0,100}\.exe/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string2312 = "detect-hooks" nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2313 = /doc\.1a\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2314 = /doc\.4a\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2315 = /doc\.bc\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2316 = /doc\.md\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2317 = /doc\.po\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2318 = /doc\.tx\..{0,100}\\\./ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2319 = "dumpwifi " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2320 = "etw stop" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2321 = "fw_walk display" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2322 = "fw_walk status" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2323 = "fw_walk total" nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2324 = "get-spns " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2325 = /Ladon\sMac\s.{0,100}\s/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string2326 = "LdapSignCheck " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2327 = /load\s.{0,100}\.cna/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string2328 = "make_token " nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string2329 = "needle_sift " nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2330 = /SigFlip\s.{0,100}\.exe/ nocase ascii wide
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
