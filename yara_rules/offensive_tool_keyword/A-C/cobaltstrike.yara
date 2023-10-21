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
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string3 = /\s.*\/lsass\.o/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string4 = /\s\.beacon_keys\s\-/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string5 = /\s\/NAME:.*\s\/KILL/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string6 = /\s\/PID:.*\s\/DRIVER:/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string7 = /\s\/PID:.*\s\/KILL/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string8 = /\s1\.2\.3\.4:8080/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string9 = /\s4444\smeter/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string10 = /\s4444\sshell/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string11 = /\samsi_disable\s/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string12 = /\sarp\.x64\.o/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string13 = /\s\-\-assemblyargs\sAntiVirus/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string14 = /\s\-\-assemblyargs\sAppLocker/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string15 = /\sbase64_encode_shellcode/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string16 = /\sbeacon\.dll/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string17 = /\sbof_allocator\s/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string18 = /\sbof_reuse_memory\s/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string19 = /\s\-BOFBytes\s/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string20 = /\sBOFNET\s/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string21 = /\sBofRunner\(/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string22 = /\sbuild\sDent\.go/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string23 = /\sbuild_letmeout/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string24 = /\sBypassUac.*\.bat/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string25 = /\sBypassUac.*\.dll/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string26 = /\sBypassUac.*\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string27 = /\s\-c\sCredEnum\.c/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string28 = /\schrome\slogindata\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string29 = /\schrome\smasterkey\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string30 = /\s\-cobalt\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string31 = /\scobaltstrike/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string32 = /\sCoffeeExecuteFunction/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string33 = /\scom\.blackh4t/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string34 = /\sCrossC2\sListener/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string35 = /\sCrossC2\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string36 = /\sCrossC2Kit\s/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string37 = /\sDelegationBOF\.c\s/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string38 = /\sdelegationx64\.o/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string39 = /\sdelegationx86\.o/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string40 = /\sDesertFox\.go/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string41 = /\sdetect\-hooks\.c\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string42 = /\s\-dns_stager_prepend\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string43 = /\s\-dns_stager_subhost\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string44 = /\s\-\-dotnetassembly\s.*\s\-\-amsi/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string45 = /\s\-\-dotnetassembly\s.*\s\-\-appdomain\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string46 = /\s\-\-dotnetassembly\s.*\s\-\-assemblyargs\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string47 = /\s\-\-dotnetassembly\s.*\s\-\-mailslot/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string48 = /\s\-\-dotnetassembly\s.*\s\-\-pipe\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string49 = /\sDraytekScan/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string50 = /\sdump_memory64/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string51 = /\sedge\slogindata\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string52 = /\sedge\smasterkey\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string53 = /\sEfsPotato/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string54 = /\sexclusion\.c\s\/Fodefender\.o/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string55 = /\s\-FakeCmdLine\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string56 = /\sFileZillaPwd/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string57 = /\sforgeTGT\(/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string58 = /\sFtpSniffer\s/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string59 = /\sgenerate_my_dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string60 = /\sgeneratePayload/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string61 = /\sGetAppLockerPolicies/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string62 = /\sGetLsassPid/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string63 = /\sgophish\-.*\.zip/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string64 = /\sHackBrowserData/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string65 = /\s\-hasbootstraphint\s/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string66 = /\sHiddenDesktop\.cna/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string67 = /\shollow\.x64\./ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string68 = /\shostenum\.py\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string69 = /\sHTTPSniffer\s/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string70 = /\s\-i\shavex\.profile\s/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string71 = /\simpacket\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string72 = /\s\-Injector\sNtMapViewOfSection/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string73 = /\s\-Injector\sVirtualAllocEx/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string74 = /\s\-isbeacon\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string75 = /\sJspShell\sua/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string76 = /\sk8gege520\s/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string77 = /\skdbof\.cpp/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string78 = /\sLadon\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string79 = /\sLadon\.py/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string80 = /\s\-\-load\-shellcode\s/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string81 = /\smalleable\.profile/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string82 = /\smalleable\-c2\-randomizer/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string83 = /\smemreader\.c\s/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string84 = /\sMemReader_BoF/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string85 = /\sms17010\s\-i\s/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string86 = /\sms17010\s\-n\s/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string87 = /\sNTLMv1\scaptured\s/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string88 = /\s\-o\s\/share\/payloads\// nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string89 = /\soxidfind\s\-i\s/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string90 = /\soxidfind\s\-n\s/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string91 = /\s\-\-payload\-types\sall/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string92 = /\s\-\-payload\-types\sbin/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string93 = /\s\-\-payload\-types\sdll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string94 = /\s\-\-payload\-types\sexe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string95 = /\s\-\-payload\-types\sps1/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string96 = /\s\-\-payload\-types\spy/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string97 = /\s\-\-payload\-types\ssvc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string98 = /\s\-\-payload\-types\svbs/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string99 = /\s\-PE_Clone\s/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string100 = /\spipename_stager\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string101 = /\s\-pipename_stager\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string102 = /\spyasn1\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string103 = /\spyasn1\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string104 = /\srai\-attack\-dns/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string105 = /\srai\-attack\-http/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string106 = /\sReadFromLsass/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string107 = /\s\-RealCmdLine\s/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string108 = /\srustbof\s/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string109 = /\sScareCrow\.go/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string110 = /\sScareCrow\.go/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string111 = /\sSeriousSam\.Execute\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string112 = /\sSetMzLogonPwd\s/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string113 = /\ssigflip\.c\s/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string114 = /\sSigFlip\.exe/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string115 = /\sSigFlip\.PE/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string116 = /\ssigflip\.x64\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string117 = /\ssigflip\.x86\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string118 = /\sSigLoader\s/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string119 = /\sSigwhatever/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string120 = /\sspawn\.x64\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string121 = /\sspawn\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string122 = /\sspawnto_x64\s/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string123 = /\sspawnto_x86\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string124 = /\sSpoolFool\s.*\.dll/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string125 = /\sStayKit\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string126 = /\sstriker\.py/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string127 = /\sSweetPotato\sby\s\@_EthicalChaos/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string128 = /\sSysWhispers/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string129 = /\sTikiLoader/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string130 = /\sTokenStrip\.c\s/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string131 = /\sTokenStripBOF\.o\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string132 = /\sTSCHRPCAttack/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string133 = /\s\-urlcache\s.*\/debase64\// nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string134 = /\s\-wordlist\s.*\s\-spawnto\s/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string135 = /\sWriteToLsass/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string136 = /\sxpipe/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string137 = /\$C2_SERVER/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string138 = /\%comspec\%\s\/k\s.*\.bat/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string139 = /\.\/c2lint\s/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string140 = /\.\/Dent\s\-/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string141 = /\.\/manjusaka/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string142 = /\.\/ScareCrow\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string143 = /\.\/SourcePoint\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string144 = /\.admin\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string145 = /\.api\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string146 = /\.apps\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string147 = /\.beta\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string148 = /\.blog\.123456\./ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string149 = /\.cobaltstrike/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string150 = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string151 = /\.com\/dcsync\// nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string152 = /\.dev\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string153 = /\.events\.123456\./ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string154 = /\.exe\s.*\s\-eventlog\s.*Key\sManagement\sService/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string155 = /\.exe\s.*\s\-\-source\sPersistence/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string156 = /\.feeds\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string157 = /\.files\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string158 = /\.forums\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string159 = /\.ftp\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string160 = /\.go\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string161 = /\.groups\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string162 = /\.help\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string163 = /\.imap\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string164 = /\.img\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string165 = /\.kb\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string166 = /\.lists\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string167 = /\.live\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string168 = /\.m\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string169 = /\.mail\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string170 = /\.media\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string171 = /\.mobile\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string172 = /\.mysql\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string173 = /\.news\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string174 = /\.photos\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string175 = /\.pic\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string176 = /\.pipename_stager/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string177 = /\.pop\.123456\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string178 = /\.py\s.*\s\-\-teamserver\s/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string179 = /\.py\s127\.0\.0\.1\s50050\slogtracker\spassword/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string180 = /\.py.*\s\-\-payload\s.*\.ps1/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string181 = /\.py.*\s\-service\-name\s.*\s\-hashes\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string182 = /\.resources\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string183 = /\.search\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string184 = /\.secure\.123456\./ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string185 = /\.sharpgen\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string186 = /\.sites\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string187 = /\.smtp\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string188 = /\.ssl\.123456\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string189 = /\.stage\.123456\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string190 = /\.stage\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string191 = /\.static\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string192 = /\.status\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string193 = /\.store\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string194 = /\.support\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string195 = /\.videos\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string196 = /\.vpn\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string197 = /\.webmail\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string198 = /\.wiki\.123456\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string199 = /\/\.aggressor\.prop/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string200 = /\/\.ssh\/RAI\.pub/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string201 = /\/\/StaticSyscallsDump\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string202 = /\/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string203 = /\/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string204 = /\/AceLdr\.cna/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string205 = /\/adcs_enum\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string206 = /\/adcs_request\/adcs_request\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string207 = /\/adcs_request\/CertCli\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string208 = /\/adcs_request\/certenroll\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string209 = /\/adcs_request\/CertPol\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string210 = /\/AddUser\-Bof\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string211 = /\/AddUser\-Bof\// nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string212 = /\/AggressiveClean\.cna/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string213 = /\/aggressor\/.*\.java/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string214 = /\/aggressor\-powerview/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string215 = /\/AggressorScripts/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string216 = /\/AggressorScripts/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string217 = /\/AggressorScripts/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string218 = /\/agscript\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string219 = /\/agscript\s/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string220 = /\/Alaris\.sln/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string221 = /\/ANGRYPUPPY\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string222 = /\/anthemtotheego\/CredBandit/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string223 = /\/artifactor\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string224 = /\/ase_docker\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string225 = /\/asprox\.profile/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string226 = /\/asprox\.profile/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string227 = /\/ASRenum\.cpp/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string228 = /\/ASRenum\.cs/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string229 = /\/ASRenum\-BOF/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string230 = /\/assets\/bin2uuids_file\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string231 = /\/AttackServers\// nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string232 = /\/auth\/cc2_auth\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string233 = /\/awesome\-pentest/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string234 = /\/backoff\.profile/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string235 = /\/backstab_src\// nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string236 = /\/BackupPrivSam\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string237 = /\/bazarloader\.profile/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string238 = /\/beacon\.h/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string239 = /\/beacon_compatibility/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string240 = /\/beacon_compatibility\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string241 = /\/beacon_funcs\// nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string242 = /\/beacon_health_check\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string243 = /\/beacon_http\// nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string244 = /\/beacon_notify\.cna/ nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string245 = /\/beaconhealth\.cna/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string246 = /\/beacon\-injection\// nocase ascii wide
        // Description: Cobaltstrike beacon object files
        // Reference: https://github.com/realoriginal/beacon-object-file
        $string247 = /\/beacon\-object\-file/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string248 = /\/BeaconTool\.java/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string249 = /\/bin\/AceLdr/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string250 = /\/bin\/Sleeper\.o/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string251 = /\/bluscreenofjeff\// nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string252 = /\/bof\.h/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string253 = /\/BOF\.NET\// nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string254 = /\/bof\.nim/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string255 = /\/bof\.x64\.o/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string256 = /\/bof\.x64\.o/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string257 = /\/bof\.x86\.o/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string258 = /\/bof\.x86\.o/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string259 = /\/bof\/bof\.c/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string260 = /\/bof\/bof\.vcxproj/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string261 = /\/bof\/IABOF/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string262 = /\/bof\/IAStart\.asm/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string263 = /\/BOF\-Builder/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string264 = /\/bof\-collection\// nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string265 = /\/BOFNETExamples\// nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string266 = /\/BOF\-RegSave/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string267 = /\/BofRunner\.cs/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string268 = /\/BOFs\.git/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string269 = /\/bof\-vs\-template\// nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string270 = /\/bof\-vs\-template\// nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string271 = /\/boku7\/spawn/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string272 = /\/boku7\/whereami\// nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string273 = /\/BokuLoader\.c/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string274 = /\/BokuLoader\.h/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string275 = /\/BokuLoader\// nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string276 = /\/BooExecutor\.cs/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string277 = /\/bq1iFEP2\/assert\/dll\// nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string278 = /\/bq1iFEP2\/assert\/exe\// nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string279 = /\/breg\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string280 = /\/breg\.x86\.o/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string281 = /\/build\/encrypted_shellcode/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string282 = /\/build\/formatted_shellcode/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string283 = /\/build\/shellcode/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string284 = /\/BuildBOFs\// nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string285 = /\/burpee\.py/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string286 = /\/BUYTHEAPTDETECTORNOW/ nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string287 = /\/BypassAV\// nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string288 = /\/bypassAV\-1\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string289 = /\/C2concealer/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string290 = /\/c2profile\./ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string291 = /\/c2profile\.go/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string292 = /\/C2script\// nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string293 = /\/cc2_frp\./ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string294 = /\/client\/bof\/.*\.asm/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string295 = /\/clipboardinject\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string296 = /\/clipboardinject\// nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string297 = /\/clipmon\/clipmon\.sln/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string298 = /\/clipmon\/dll\// nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string299 = /\/cna\/pipetest\.cna/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string300 = /\/cobaltclip\.c/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string301 = /\/cobaltclip\.o/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string302 = /\/Cobalt\-Clip\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string303 = /\/cobaltstrike/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string304 = /\/cobalt\-strike/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string305 = /\/CoffeeLdr\.c/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string306 = /\/CoffeeLdr\// nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string307 = /\/COFFLoader/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string308 = /\/COFFLoader2\// nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string309 = /\/com\/blackh4t\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string310 = /\/comfoo\.profile/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string311 = /\/CookieProcessor\.cs/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string312 = /\/core\/browser_darwin\.go/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string313 = /\/core\/browser_linux\.go/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string314 = /\/core\/browser_windows\.go/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string315 = /\/Cracked5pider\// nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string316 = /\/credBandit\// nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string317 = /\/CredEnum\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string318 = /\/CredEnum\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string319 = /\/CredEnum\.h/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string320 = /\/CredPrompt\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string321 = /\/CredPrompt\/credprompt\.c/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string322 = /\/CrossC2\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string323 = /\/CrossC2\// nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string324 = /\/CrossC2Kit/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string325 = /\/CrossC2Kit\// nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string326 = /\/CrossNet\-Beta\// nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string327 = /\/crypt0p3g\// nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string328 = /\/cs2modrewrite\// nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string329 = /\/CS\-BOFs\// nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string330 = /\/CSharpWinRM/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string331 = /\/C\-\-Shellcode/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string332 = /\/CS\-Loader\.go/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string333 = /\/CS\-Loader\// nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string334 = /\/csOnvps\// nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string335 = /\/csOnvps\// nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string336 = /\/cs\-rdll\-ipc\-example\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string337 = /\/CS\-Remote\-OPs\-BOF/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string338 = /\/cs\-token\-vault\// nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string339 = /\/curl\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string340 = /\/curl\.x64\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string341 = /\/curl\.x86\.o/ nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string342 = /\/custom_payload_generator\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string343 = /\/CWoNaJLBo\/VTNeWw11212\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string344 = /\/CWoNaJLBo\/VTNeWw11213\// nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string345 = /\/DCOM\sLateral\sMovement\// nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string346 = /\/defender\-exclusions\/.*defender/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string347 = /\/defender\-exclusions\/.*exclusion/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string348 = /\/DelegationBOF\// nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string349 = /\/demo_bof\.c/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string350 = /\/Dent\/.*\/Loader\/Loader\.go/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string351 = /\/Dent\/Dent\.go/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string352 = /\/Dent\/Loader/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string353 = /\/DesertFox\/archive\/.*\.zip/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string354 = /\/detect\-hooks\.c/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string355 = /\/detect\-hooks\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string356 = /\/detect\-hooks\.h/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string357 = /\/Detect\-Hooks\// nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string358 = /\/dist\/fw_walk\./ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string359 = /\/DLL\-Hijack/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string360 = /\/Doge\-Loader\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string361 = /\/DotNet\/SigFlip/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string362 = /\/dukes_apt29\.profile/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string363 = /\/dump_lsass\./ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string364 = /\/dumpert\.c/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string365 = /\/Dumpert\// nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string366 = /\/dumpXor\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string367 = /\/dumpXor\/dumpXor/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string368 = /\/ElevateKit\/elevate\./ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string369 = /\/ELFLoader\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string370 = /\/emotet\.profile/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string371 = /\/enableuser\/enableuser\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string372 = /\/enableuser\/enableuser\.x86\./ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string373 = /\/EnumCLR\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string374 = /\/enumerate\.cna/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string375 = /\/Erebus\/.*\.dll/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string376 = /\/Erebus\/.*\.exe/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string377 = /\/Erebus\-email\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string378 = /\/etumbot\.profile/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string379 = /\/etw\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string380 = /\/etw\.x64\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string381 = /\/etw\.x86\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string382 = /\/EventViewerUAC\// nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string383 = /\/EventViewerUAC\// nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string384 = /\/evil\.cpp/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string385 = /\/exports_function_hid\.txt/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string386 = /\/fiesta\.profile/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string387 = /\/fiesta2\.profile/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string388 = /\/final_shellcode_size\.txt/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string389 = /\/FindModule\.c/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string390 = /\/FindObjects\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string391 = /\/Fodetect\-hooksx64/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string392 = /\/FuckThatPacker/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string393 = /\/G0ldenGunSec\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string394 = /\/gandcrab\.profile/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string395 = /\/geacon\/.*beacon/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string396 = /\/geacon_pro/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string397 = /\/get\-loggedon\/.*\.c/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string398 = /\/get\-system\/getsystem\.c/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string399 = /\/GetWebDAVStatus_BOF\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string400 = /\/globeimposter\.profile/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string401 = /\/guervild\/BOFs/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string402 = /\/hancitor\.profile/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com/EspressoCake/HandleKatz_BOF
        $string403 = /\/HandleKatz_BOF/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string404 = /\/HaryyUser\.exe/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string405 = /\/havex\.profile/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string406 = /\/HiddenDesktop\.git/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string407 = /\/hollow\.x64\./ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string408 = /\/hooks\/spoof\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string409 = /\/hostenum\.py/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string410 = /\/HouQing\/.*\/Loader\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string411 = /\/injectAmsiBypass\// nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string412 = /\/inject\-assembly\// nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string413 = /\/injectEtw\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string414 = /\/Injection\/clipboard\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string415 = /\/Injection\/conhost\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string416 = /\/Injection\/createremotethread\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string417 = /\/Injection\/ctray\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string418 = /\/Injection\/dde\// nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string419 = /\/Injection\/Injection\.cna/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string420 = /\/Injection\/kernelcallbacktable/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string421 = /\/Injection\/ntcreatethread/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string422 = /\/Injection\/ntcreatethread\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string423 = /\/Injection\/ntqueueapcthread/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string424 = /\/Injection\/setthreadcontext/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string425 = /\/Injection\/svcctrl\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string426 = /\/Injection\/tooltip\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string427 = /\/Injection\/uxsubclassinfo/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string428 = /\/InlineWhispers/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string429 = /\/Internals\/Coff\.cs/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string430 = /\/Inveigh\.txt/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string431 = /\/Invoke\-Bof\// nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string432 = /\/Invoke\-HostEnum\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string433 = /\/jaff\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string434 = /\/jasperloader\.profile/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string435 = /\/K8_CS_.*_.*\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string436 = /\/k8gege\// nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string437 = /\/k8gege\/scrun\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string438 = /\/k8gege520/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string439 = /\/kdstab\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string440 = /\/KDStab\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string441 = /\/KDStab\// nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string442 = /\/KernelMii\.c/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string443 = /\/Koh\/.*\.cs/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string444 = /\/kronos\.profile/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string445 = /\/Ladon\.go/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string446 = /\/Ladon\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string447 = /\/Ladon\.py/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string448 = /\/Ladon\/Ladon\./ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string449 = /\/Ladon\/obj\/x86/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string450 = /\/LadonGo\// nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string451 = /\/LetMeOutSharp\// nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string452 = /\/lib\/ipLookupHelper\.py/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string453 = /\/loader\/x64\/Release\/loader\.exe/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string454 = /\/loadercrypt_.*\.php/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string455 = /\/logs\/.*\/becon_.*\.log/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string456 = /\/logs\/beacon_log/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string457 = /\/lpBunny\/bof\-registry/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string458 = /\/lsass\/beacon\.h/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string459 = /\/magnitude\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string460 = /\/malleable\-c2/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string461 = /\/manjusaka\/plugins/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string462 = /\/MemReader_BoF\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string463 = /\/mimipenguin\.c/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string464 = /\/mimipenguin\// nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string465 = /\/minimal_elf\.h/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string466 = /\/Misc\/donut\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string467 = /\/Mockingjay_BOF\.git/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string468 = /\/Modules\/Exitservice\/uinit\.exe/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string469 = /\/Mr\-Un1k0d3r\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string470 = /\/Native\/SigFlip\// nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string471 = /\/nccgroup\/nccfsas\// nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string472 = /\/Needle_Sift_BOF\// nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string473 = /\/nettitude\/RunOF\// nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string474 = /\/NetUser\.cpp/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string475 = /\/NetUser\.exe/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string476 = /\/netuserenum\// nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string477 = /\/Network\/PortScan\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string478 = /\/Newtonsoft\.Json\.dll/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string479 = /\/ntlmrelayx\// nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string480 = /\/oab\-parse\/mspack\..*\.dll/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string481 = /\/OG\-Sadpanda\// nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string482 = /\/On_Demand_C2\// nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string483 = /\/opt\/implant\// nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string484 = /\/opt\/rai\// nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string485 = /\/optiv\/Dent\// nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string486 = /\/oscp\.profile/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string487 = /\/outflanknl\// nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string488 = /\/output\/payloads\// nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string489 = /\/p292\/Phant0m/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string490 = /\/package\/portscan\/.*\.go/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string491 = /\/password\/mimipenguin\// nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string492 = /\/payload_scripts/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string493 = /\/payload_scripts\/artifact/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string494 = /\/PersistBOF\// nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string495 = /\/PhishingServer\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string496 = /\/pitty_tiger\.profile/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string497 = /\/popCalc\.bin/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string498 = /\/PortBender\// nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string499 = /\/portscan\.cna/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string500 = /\/POSeidon\.profile/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string501 = /\/PowerView\.cna/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string502 = /\/PowerView3\.cna/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string503 = /\/PPEnum\// nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string504 = /\/ppldump\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string505 = /\/PPLDump_BOF\// nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string506 = /\/PrintMonitorDll\./ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string507 = /\/PrintMonitorDll\// nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string508 = /\/PrintSpoofer\// nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string509 = /\/PrivilegeEscalation\// nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string510 = /\/proberbyte\.go/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string511 = /\/Proxy_Def_File_Generator\.cna/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string512 = /\/putter\.profile/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string513 = /\/pyasn1\// nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string514 = /\/pycobalt\-/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string515 = /\/pycobalt\// nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string516 = /\/pystinger\.zip/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string517 = /\/qakbot\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string518 = /\/quantloader\.profile/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string519 = /\/RAI\.git/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string520 = /\/ramnit\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string521 = /\/ratankba\.profile/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string522 = /\/raw_shellcode_size\.txt/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string523 = /\/RC4Payload32\.txt/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string524 = /\/RCStep\/CSSG\// nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string525 = /\/readfile_bof\./ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string526 = /\/Readfile_BoF\// nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string527 = /\/red\-team\-scripts/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string528 = /\/RedWarden\.git/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string529 = /\/RegistryPersistence\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string530 = /\/Registry\-Recon\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string531 = /\/Remote\/adcs_request\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string532 = /\/Remote\/office_tokens\// nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string533 = /\/Remote\/procdump\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string534 = /\/Remote\/ProcessDestroy\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string535 = /\/Remote\/ProcessListHandles\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string536 = /\/Remote\/schtaskscreate\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string537 = /\/Remote\/schtasksrun\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string538 = /\/Remote\/setuserpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string539 = /\/Remote\/setuserpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string540 = /\/Remote\/unexpireuser\// nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string541 = /\/remotereg\.c/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string542 = /\/remotereg\.o/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string543 = /\/RunOF\/RunOF\// nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string544 = /\/runshellcode\./ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string545 = /\/S3cur3Th1sSh1t\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string546 = /\/saefko\.profile/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string547 = /\/ScareCrow\s\-I\s/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string548 = /\/ScRunHex\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string549 = /\/searchsploit/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string550 = /\/Seatbelt\.txt/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string551 = /\/secinject\.c/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string552 = /\/self_delete\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string553 = /\/SeriousSam\.sln/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string554 = /\/serverscan\/CobaltStrike/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string555 = /\/serverscan_Air/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string556 = /\/serverscan_pro/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string557 = /\/ServerScanForLinux\// nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string558 = /\/ServerScanForWindows\// nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string559 = /\/ServerScanForWindows\/PE/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string560 = /\/ServiceMove\-BOF\// nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string561 = /\/Services\/TransitEXE\.exe/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string562 = /\/setuserpass\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string563 = /\/setuserpass\.x86\./ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string564 = /\/SharpCalendar\/.*\./ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string565 = /\/SharpCat\// nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string566 = /\/SharpCompile\// nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string567 = /\/sharpcompile_.*\./ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string568 = /\/SharpCradle\// nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string569 = /\/SharpSword\/SharpSword/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string570 = /\/ShellCode_Loader/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string571 = /\/shspawnas\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string572 = /\/sigflip\.x64\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string573 = /\/sigflip\.x86\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string574 = /\/SigLoader\.go/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string575 = /\/SigLoader\// nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string576 = /\/SilentClean\.exe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string577 = /\/SilentClean\/SilentClean\/.*\.cs/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string578 = /\/silentdump\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string579 = /\/silentdump\.h/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string580 = /\/sleep_python_bridge\// nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string581 = /\/Sleeper\/Sleeper\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string582 = /\/sleepmask\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string583 = /\/spawn\.git/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string584 = /\/spoolsystem\/SpoolTrigger\// nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string585 = /\/Spray\-AD\./ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string586 = /\/Spray\-AD\// nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string587 = /\/src\/Sleeper\.cpp/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string588 = /\/StaticSyscallsAPCSpawn\// nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string589 = /\/StaticSyscallsInject\// nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string590 = /\/StayKit\.cna/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string591 = /\/Staykit\/StayKit\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string592 = /\/striker\.py/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string593 = /\/string_of_paerls\.profile/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string594 = /\/suspendresume\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string595 = /\/suspendresume\.x86/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string596 = /\/SweetPotato_CS/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string597 = /\/SyscallsInject\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string598 = /\/taidoor\.profile/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string599 = /\/tcpshell\.py/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string600 = /\/test32\.dll/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string601 = /\/test64\.dll/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string602 = /\/tests\/test\-bof\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string603 = /\/tevora\-threat\/PowerView/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string604 = /\/tgtParse\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string605 = /\/tgtParse\/tgtParse\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string606 = /\/ticketConverter\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string607 = /\/TikiLoader\// nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string608 = /\/TikiSpawn\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string609 = /\/TikiSpawn\// nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string610 = /\/TokenStripBOF/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string611 = /\/tools\/BeaconTool\// nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string612 = /\/Tools\/spoolsystem\// nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string613 = /\/Tools\/Squeak\/Squeak/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string614 = /\/trick_ryuk\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string615 = /\/trickbot\.profile/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string616 = /\/UAC\-SilentClean\// nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string617 = /\/unhook\-bof/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/Cobalt-Strike/unhook-bof
        $string618 = /\/unhook\-bof/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string619 = /\/UTWOqVQ132\// nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string620 = /\/vssenum\// nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string621 = /\/WdToggle\.c/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string622 = /\/WdToggle\.h/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string623 = /\/webshell\/.*\.aspx/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string624 = /\/webshell\/.*\.jsp/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string625 = /\/webshell\/.*\.php/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string626 = /\/wifidump\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string627 = /\/WindowsVault\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string628 = /\/WindowsVault\.h/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string629 = /\/winrm\.cpp/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string630 = /\/winrmdll/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string631 = /\/winrm\-reflective\-dll\// nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string632 = /\/Winsocky\.git/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string633 = /\/WMI\sLateral\sMovement\// nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string634 = /\/wwlib\/lolbins\// nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string635 = /\/xen\-mimi\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string636 = /\/xor\/stager\.txt/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string637 = /\/xor\/xor\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string638 = /\/xPipe\// nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string639 = /\/yanghaoi\/_CNA/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string640 = /\/zerologon\.cna/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string641 = /\[\'spawnto\'\]/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string642 = /\\\\GetWebDAVStatus\.exe/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string643 = /\\\\pipe\\\\DAV\sRPC\sSERVICE/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string644 = /\\8e8988b257e9dd2ea44ff03d44d26467b7c9ec16/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string645 = /\\beacon\.exe/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string646 = /\\CrossC2\./ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string647 = /\\CROSSNET\\CROSSNET\\/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string648 = /\\dumpert\./ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string649 = /\\Dumpert\\/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string650 = /\\DumpShellcode/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string651 = /\\dumpXor\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string652 = /\\dumpXor\\x64\\/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string653 = /\\ELF\\portscan/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string654 = /\\ELF\\serverscan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string655 = /\\evil\.dll/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string656 = /\\GetWebDAVStatus\\/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string657 = /\\GetWebDAVStatus_x64/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string658 = /\\HackBrowserData/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string659 = /\\HiddenDesktop\\/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string660 = /\\HostEnum\.ps1/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string661 = /\\kdstab\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string662 = /\\Koh\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string663 = /\\Koh\.pdb/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string664 = /\\Koh\\Koh\./ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string665 = /\\Ladon\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string666 = /\\Ladon\.ps1/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string667 = /\\LogonScreen\.exe/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string668 = /\\lsass\.dmp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string669 = /\\Mockingjay_BOF\./ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string670 = /\\portbender\./ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string671 = /\\PowerView\.cna/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string672 = /\\PowerView\.exe/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string673 = /\\PowerView\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string674 = /\\PowerView3\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string675 = /\\RunBOF\.exe/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string676 = /\\RunOF\.exe/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string677 = /\\RunOF\\bin\\/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string678 = /\\samantha\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string679 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string680 = /\\SigFlip\.exe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string681 = /\\SilentClean\.exe/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string682 = /\\StayKit\.cna/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string683 = /\\systemic\.txt/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string684 = /\\TASKSHELL\.EXE/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string685 = /\\TikiCompiler\.txt/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string686 = /\\TikiService\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string687 = /\\TikiSpawn\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string688 = /\\tikispawn\.xml/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string689 = /\\TikiTorch\\Aggressor/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string690 = /_cobaltstrike/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string691 = /_find_sharpgen_dll/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string692 = /_pycobalt_/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string693 = /_tcp_cc2\(/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string694 = /_udp_cc2\(/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string695 = /\<CoffeLdr\.h\>/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string696 = /0xthirteen\/MoveKit/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string697 = /0xthirteen\/StayKit/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string698 = /0xthirteen\/StayKit/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string699 = /4d5350c8\-7f8c\-47cf\-8cde\-c752018af17e/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string700 = /516280565958/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string701 = /516280565959/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string702 = /5a40f11a99d0db4a0b06ab5b95c7da4b1c05b55a99c7c443021bff02c2cf93145c53ff5b/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string703 = /5e98194a01c6b48fa582a6a9fcbb92d6/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string704 = /5e98194a01c6b48fa582a6a9fcbb92d6/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string705 = /6e7645c4\-32c5\-4fe3\-aabf\-e94c2f4370e7/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string706 = /713724C3\-2367\-49FA\-B03F\-AB4B336FB405/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string707 = /7CFC52\.dll/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string708 = /7CFC52CD3F\.dll/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string709 = /913d774e5cf0bfad4adfa900997f7a1a/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string710 = /913d774e5cf0bfad4adfa900997f7a1a/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string711 = /AceLdr\..*\.bin/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string712 = /AceLdr\.zip/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string713 = /adcs_enum\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string714 = /adcs_enum_com\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string715 = /adcs_enum_com2\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string716 = /AddUser\-Bof\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string717 = /AddUser\-Bof\.git/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string718 = /AddUser\-Bof\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string719 = /AddUser\-Bof\.x64/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string720 = /AddUser\-Bof\.x86/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string721 = /AddUserToDomainGroup\s.*Domain\sAdmins/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string722 = /AddUserToDomainGroup\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string723 = /AddUserToDomainGroup\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string724 = /Adminisme\/ServerScan\// nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string725 = /ag_load_script/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string726 = /AggressiveProxy\.cna/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string727 = /aggressor\.beacons/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string728 = /aggressor\.bshell/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string729 = /aggressor\.cna/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string730 = /aggressor\.dialog/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string731 = /aggressor\.println/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string732 = /aggressor\.py/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string733 = /Aggressor\/TikiTorch/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string734 = /Aggressor\-Scripts/ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string735 = /aggressor\-scripts/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string736 = /ajpc500\/BOFs/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string737 = /Alphabug_CS/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string738 = /Alphabug_CS/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string739 = /AlphabugX\/csOnvps/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string740 = /AlphabugX\/csOnvps/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string741 = /Already\sSYSTEM.*not\selevating/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string742 = /ANGRYPUPPY2\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string743 = /anthemtotheego\/Detect\-Hooks/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string744 = /apokryptein\/secinject/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string745 = /applocker_enum/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string746 = /applocker\-enumerator/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string747 = /apt1_virtuallythere\.profile/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string748 = /arsenal_kit\.cna/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string749 = /artifact\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string750 = /artifact\.cna/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string751 = /artifact\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string752 = /artifact\.x64\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string753 = /artifact\.x86\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string754 = /artifact\.x86\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string755 = /artifact_payload/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string756 = /artifact_payload/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string757 = /artifact_stageless/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string758 = /artifact_stageless/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string759 = /artifact_stager/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string760 = /artifact_stager/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string761 = /artifact32.*\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string762 = /artifact32\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string763 = /artifact32\.dll/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string764 = /artifact32\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string765 = /artifact32\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string766 = /artifact32big\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string767 = /artifact32big\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string768 = /artifact32svc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string769 = /artifact32svcbig\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string770 = /artifact64.*\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string771 = /artifact64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string772 = /artifact64\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string773 = /artifact64\.x64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string774 = /artifact64big\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string775 = /artifact64big\.x64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string776 = /artifact64svc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string777 = /artifact64svcbig\.exe/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string778 = /artifactbig64\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string779 = /artifactuac.*\.dll/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string780 = /ASRenum\-BOF\./ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string781 = /Assemblies\/SharpMove\.exe/ nocase ascii wide
        // Description: Cobalt Strike BOFs
        // Reference: https://github.com/AttackTeamFamily/cobaltstrike-bof-toolset
        $string782 = /AttackTeamFamily.*\-bof\-toolset/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string783 = /ausecwa\/bof\-registry/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string784 = /auth\/cc2_ssh\./ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string785 = /Backdoor\sLNK/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string786 = /\-\-backdoor\-all/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string787 = /backdoorlnkdialog/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string788 = /backstab\.x64\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string789 = /backstab\.x86\./ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string790 = /BackupPrivSAM\s\\\\/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string791 = /backupprivsam\./ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string792 = /BadPotato\.exe/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string793 = /bawait_upload/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string794 = /bawait_upload_raw/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string795 = /bblockdlls/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string796 = /bbrowserpivot/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string797 = /bbrowserpivot/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string798 = /bbypassuac/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string799 = /bcc2_setenv/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string800 = /bcc2_spawn/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string801 = /bcrossc2_load_dyn/ nocase ascii wide
        // Description: Malleable C2 Profiles. A collection of profiles used in different projects using Cobalt Strike & Empire.
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string802 = /BC\-SECURITY.*Malleable/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string803 = /bdcsync/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string804 = /bdllinject/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string805 = /bdllinject/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string806 = /bdllload/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string807 = /bdllload/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string808 = /bdllspawn/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string809 = /bdllspawn/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string810 = /Beacon\sPayload\sGenerator/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string811 = /beacon\..*winsrv\.dll/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string812 = /beacon\.CommandBuilder/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string813 = /beacon\.CommandBuilder/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string814 = /beacon\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string815 = /beacon\.exe/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string816 = /beacon\.exe/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string817 = /beacon\.nim/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string818 = /Beacon\.Object\.File\.zip/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string819 = /beacon\.x64.*\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string820 = /beacon\.x64.*\.exe/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string821 = /beacon\.x64\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string822 = /beacon\.x86.*\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string823 = /beacon\.x86.*\.exe/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string824 = /beacon_api\.h/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string825 = /beacon_bottom\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string826 = /Beacon_Com_Struct/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string827 = /beacon_command_describe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string828 = /beacon_command_detail/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string829 = /beacon_command_detail/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string830 = /beacon_command_register/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string831 = /beacon_command_register/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string832 = /beacon_commands/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string833 = /beacon_compatibility\.c/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string834 = /beacon_compatibility\.h/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string835 = /beacon_elevator_describe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string836 = /beacon_elevator_describe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string837 = /beacon_elevator_register/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string838 = /beacon_elevator_register/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string839 = /beacon_elevator_register/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string840 = /beacon_elevators/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string841 = /beacon_elevators/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string842 = /beacon_execute_job/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string843 = /beacon_exploit_describe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string844 = /beacon_exploit_register/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string845 = /beacon_funcs\.c/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string846 = /beacon_funcs\.h/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string847 = /beacon_funcs\.x64\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string848 = /beacon_funcs\.x86\./ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string849 = /beacon_generate\.py/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string850 = /Beacon_GETPOST/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string851 = /beacon_host_script/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string852 = /beacon_host_script/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string853 = /beacon_inline_execute/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string854 = /beacon_inline_execute/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string855 = /beacon_inline_execute/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string856 = /beacon_inline_execute/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string857 = /beacon_log_clean/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string858 = /beacon_output_ps\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string859 = /beacon_print/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string860 = /BEACON_RDLL_/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string861 = /beacon_remote_exec_/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string862 = /beacon_remote_exec_method_describe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string863 = /beacon_remote_exec_method_register/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string864 = /beacon_remote_exec_methods/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string865 = /beacon_remote_exploit/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string866 = /beacon_remote_exploit_arch/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string867 = /beacon_remote_exploit_describe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string868 = /beacon_remote_exploit_register/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string869 = /beacon_remote_exploits/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string870 = /beacon_smb\.exe/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string871 = /Beacon_Stage_p2_Stuct/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string872 = /beacon_stage_pipe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string873 = /beacon_stage_pipe/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string874 = /Beacon_Stage_Struct_p1/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string875 = /Beacon_Stage_Struct_p3/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string876 = /beacon_stage_tcp/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string877 = /beacon_stage_tcp/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string878 = /beacon_test\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string879 = /beacon_top\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string880 = /beacon_top_callback/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string881 = /BeaconApi\.cs/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string882 = /beacon\-c2\-go/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string883 = /BeaconCleanupProcess/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string884 = /BeaconConsoleWriter\.cs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string885 = /BeaconGetSpawnTo/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string886 = /BeaconGetSpawnTo/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string887 = /BeaconGetSpawnTo/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string888 = /beacongrapher\.py/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string889 = /BeaconInjectProcess/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string890 = /BeaconInjectProcess/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string891 = /BeaconInjectTemporaryProcess/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string892 = /BeaconInjectTemporaryProcess/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string893 = /BeaconJob\.cs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string894 = /BeaconJobWriter\.cs/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string895 = /beaconlogs\.json/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string896 = /beaconlogtracker\.py/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string897 = /BeaconNote\.cna/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string898 = /BeaconNotify\.cna/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string899 = /BeaconObject\.cs/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string900 = /BeaconOutputStreamW/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string901 = /BeaconOutputWriter\.cs/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string902 = /BeaconPrintf\(/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string903 = /BeaconPrintf/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string904 = /BeaconPrintToStreamW/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string905 = /BeaconSpawnTemporaryProcess/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string906 = /BeaconSpawnTemporaryProcess/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string907 = /BeaconTool\s\-/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string908 = /BeaconTool\/lib\/sleep\.jar/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string909 = /BeaconUseToken/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string910 = /bgetprivs/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string911 = /bhashdump/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string912 = /bin\/bof_c\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string913 = /bin\/bof_nim\.o/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string914 = /bkerberos_ccache_use/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string915 = /bkerberos_ticket_purge/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string916 = /bkerberos_ticket_use/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string917 = /bkeylogger/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string918 = /blockdlls\sstart/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string919 = /blockdlls\sstop/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string920 = /bloginuser/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string921 = /blogonpasswords/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string922 = /BOF\sprototype\sworks\!/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string923 = /bof.*\/CredEnum\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string924 = /BOF\/.*procdump\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string925 = /bof_allocator/ nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string926 = /bof_helper\.py/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string927 = /bof_net_user\.c/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string928 = /bof_net_user\.o/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string929 = /bof_reuse_memory/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string930 = /BOF2shellcode/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string931 = /bof2shellcode\.py/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string932 = /BOF\-DLL\-Inject/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string933 = /bofentry::bof_entry/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string934 = /BOF\-ForeignLsass/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string935 = /BOF\-IShellWindows\-DCOM\./ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string936 = /BofLdapSignCheck/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string937 = /bofloader\.bin/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string938 = /bofnet.*SeriousSam\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string939 = /BOFNET\.Bofs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string940 = /bofnet\.cna/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string941 = /BOFNET\.csproj/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string942 = /BOFNET\.sln/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string943 = /bofnet_boo\s.*\.boo/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string944 = /bofnet_execute\s/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string945 = /bofnet_execute\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string946 = /bofnet_init/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string947 = /bofnet_job\s/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string948 = /bofnet_jobkill/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string949 = /bofnet_jobs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string950 = /bofnet_jobstatus\s/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string951 = /bofnet_list/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string952 = /bofnet_listassembiles/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string953 = /bofnet_load\s.*\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string954 = /bofnet_shutdown/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string955 = /BOFNET_Tests/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string956 = /bofportscan\s/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string957 = /bof\-quser\s.*\./ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string958 = /bof\-quser\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string959 = /bof\-rdphijack/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string960 = /bof\-regsave\s/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string961 = /BofRunnerOutput/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string962 = /BOFs.*\/SyscallsSpawn\// nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string963 = /Bofs\/AssemblyLoader/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string964 = /bof\-servicemove\s/ nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string965 = /bof\-trustedpath\-uacbypass/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string966 = /boku_pe_customMZ/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string967 = /boku_pe_customPE/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string968 = /boku_pe_dll/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string969 = /boku_pe_mask_/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string970 = /boku_pe_MZ_from_C2Profile/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string971 = /boku_strrep/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string972 = /boku7\/BokuLoader/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string973 = /boku7\/HOLLOW/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string974 = /BokuLoader\.cna/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string975 = /BokuLoader\.exe/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string976 = /BokuLoader\.x64/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string977 = /BooExecutorImpl\.cs/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string978 = /bpassthehash/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string979 = /bpowerpick/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string980 = /bpsexec_command/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string981 = /bpsexec_command/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string982 = /bpsexec_psh/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string983 = /bpsinject/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string984 = /bpsinject/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string985 = /breg\sadd\s.*HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string986 = /breg\sdelete\s.*HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string987 = /breg\squery\s.*HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string988 = /breg_add_string_value/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string989 = /bremote_exec/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string990 = /browser_\#\#/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string991 = /browserpivot\s/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string992 = /brun_script_in_mem/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string993 = /brunasadmin/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string994 = /bshinject/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string995 = /bshinject/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string996 = /bshspawn/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string997 = /bsteal_token/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string998 = /bsteal_token/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string999 = /build\sSourcePoint\.go/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1000 = /build\/breg\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1001 = /build_c_shellcode/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1002 = /BuildBOFs\.exe/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1003 = /BuildBOFs\.sln/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1004 = /bupload_raw.*\.dll/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1005 = /burp2malleable\./ nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string1006 = /BypassAV\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1007 = /bypass\-pipe\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string1008 = /byt3bl33d3r\/BOF\-Nim/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1009 = /\-c\sBOF\.cpp\s\-o\sBOF\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1010 = /\-c\sBOF\.cpp\s\-o\sBOF\.x64\.o/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1011 = /C:\\Temp\\poc\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1012 = /C:\\Windows\\Temp\\move\.exe/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1013 = /C:\\Windows\\Temp\\moveme\.exe/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1014 = /C\?\?\/generator\.cpp/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1015 = /c2lint\s/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1016 = /C2ListenerPort/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1017 = /\-c2\-randomizer\.py/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1018 = /C2ReverseClint/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1019 = /C2ReverseProxy/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1020 = /C2ReverseServer/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1021 = /C2script\/proxy\./ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1022 = /\'c2server\'/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1023 = /CACTUSTORCH\.cna/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1024 = /CACTUSTORCH\.cs/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1025 = /CACTUSTORCH\.hta/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1026 = /CACTUSTORCH\.js/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1027 = /CACTUSTORCH\.vba/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1028 = /CACTUSTORCH\.vbe/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1029 = /CACTUSTORCH\.vbs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1030 = /CALLBACK_HASHDUMP/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1031 = /CALLBACK_KEYSTROKES/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1032 = /CALLBACK_NETVIEW/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1033 = /CALLBACK_PORTSCAN/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1034 = /CALLBACK_TOKEN_STOLEN/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1035 = /CallBackDump.*dumpXor/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1036 = /CallbackDump\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1037 = /careCrow.*_linux_amd64/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1038 = /cat\s.*\.bin\s\|\sbase64\s\-w\s0\s\>\s.*\.txt/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1039 = /cc2_keystrokes_/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1040 = /cc2_mimipenguin\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1041 = /cc2_portscan_/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1042 = /cc2_rebind_.*_get_recv/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1043 = /cc2_rebind_.*_get_send/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1044 = /cc2_rebind_.*_post_recv/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1045 = /cc2_rebind_.*_post_send/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1046 = /cc2_udp_server/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1047 = /cc2FilesColor\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1048 = /cc2ProcessColor\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1049 = /CCob\/BOF\.NET/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1050 = /cd\s\.\/whereami\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1051 = /ChatLadon\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1052 = /ChatLadon\.rar/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1053 = /check_and_write_IAT_Hook/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1054 = /check_function\sntdll\.dll\sEtwEventWrite/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1055 = /checkIfHiddenAPICall/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1056 = /chromeKey\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1057 = /chromeKey\.x86/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1058 = /chromiumkeydump/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1059 = /cHux014r17SG3v4gPUrZ0BZjDabMTY2eWDj1tuYdREBg/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1060 = /clipboardinject\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1061 = /clipboardinject\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1062 = /clipboardinject\.x86/ nocase ascii wide
        // Description: CLIPBRDWNDCLASS process injection technique(BOF) - execute beacon shellcode in callback
        // Reference: https://github.com/BronzeTicket/ClipboardWindow-Inject
        $string1063 = /ClipboardWindow\-Inject/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1064 = /clipmon\.sln/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1065 = /Cobalt\sStrike/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1066 = /cobaltclip\.cna/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1067 = /cobaltclip\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1068 = /cobaltstrike\s/ nocase ascii wide
        // Description: cobaltstrike binary for windows - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network. While penetration tests focus on unpatched vulnerabilities and misconfigurations. these assessments benefit security operations and incident response.
        // Reference: https://www.cobaltstrike.com/
        $string1069 = /cobaltstrike/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1070 = /cobaltstrike\-/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1071 = /cobalt\-strike/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1072 = /\-cobaltstrike/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1073 = /cobaltstrike\./ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1074 = /cobaltstrike\.store/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1075 = /cobaltstrike\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1076 = /cobaltstrike_/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1077 = /CodeLoad\(shellcode\)/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1078 = /coff_definitions\.h/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1079 = /COFF_Loader\./ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1080 = /COFF_PREP_BEACON/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1081 = /CoffeeLdr.*\sgo\s/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1082 = /CoffeeLdr\.x64\.exe/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1083 = /CoffeeLdr\.x86\.exe/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1084 = /COFFELDR_COFFELDR_H/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1085 = /COFFLoader\./ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1086 = /COFFLoader64\.exe/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1087 = /com_exec_go\(/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1088 = /com\-exec\.cna/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1089 = /common\.ReflectiveDLL/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string1090 = /common\.ReflectiveDLL/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1091 = /comnap_\#\#/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1092 = /comnode_\#\#/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1093 = /connormcgarr\/tgtdelegation/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1094 = /cookie_graber_x64\.o/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1095 = /cookie\-graber\.c/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1096 = /cookie\-graber_x64\.exe/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1097 = /Cookie\-Graber\-BOF/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1098 = /CookieProcessor\.exe/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1099 = /covid19_koadic\.profile/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1100 = /crawlLdrDllList/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1101 = /credBandit\s.*\soutput/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1102 = /credBandit\./ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1103 = /credBanditx64/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string1104 = /CredPrompt\/CredPrompt\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1105 = /cribdragg3r\/Alaris/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1106 = /crimeware.*\/zeus\.profile/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1107 = /crisprss\/PrintSpoofer/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1108 = /CrossC2\sbeacon/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1109 = /CrossC2\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1110 = /crossc2_entry/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1111 = /crossc2_portscan\./ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1112 = /crossc2_serverscan\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1113 = /CrossC2Beacon/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1114 = /CrossC2Kit\./ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1115 = /CrossC2Kit\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1116 = /CrossC2Kit\.git/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1117 = /CrossC2Kit_demo/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1118 = /crossc2kit_latest/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1119 = /CrossC2Kit_Loader/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1120 = /CrossC2Listener/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1121 = /CrossC2MemScriptEng/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1122 = /CrossC2Script/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1123 = /CrossNet\.exe/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1124 = /CRTInjectAsSystem/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1125 = /CRTInjectElevated/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1126 = /CRTInjectWithoutPid/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1127 = /cs2modrewrite\.py/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1128 = /cs2nginx\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1129 = /CS\-Avoid\-killing/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1130 = /CS\-BOFs\/lsass/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1131 = /CSharpNamedPipeLoader/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1132 = /csload\.net\/.*\/muma\./ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1133 = /csOnvps.*teamserver/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1134 = /CS\-Remote\-OPs\-BOF/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string1135 = /CSSG_load\.cna/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1136 = /cs\-token\-vault\.git/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1137 = /cube0x0\/LdapSignCheck/ nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string1138 = /custom_payload_generator\./ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1139 = /CustomKeyboardLayoutPersistence/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1140 = /CVE_20.*\.dll/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1141 = /cve\-20\.x64\.dll/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1142 = /cve\-20\.x86\.dll/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1143 = /DallasFR\/Cobalt\-Clip/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1144 = /darkr4y\/geacon/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1145 = /dcsync\@protonmail\.com/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1146 = /dcsyncattack\(/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1147 = /dcsyncattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1148 = /dcsyncclient\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1149 = /dcsyncclient\.py/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1150 = /DeEpinGh0st\/Erebus/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1151 = /DefaultBeaconApi/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1152 = /demo\-bof\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string1153 = /detect\-hooksx64\./ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1154 = /DisableAllWindowsSoftwareFirewalls/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1155 = /disableeventvwr\/.*\.ps1/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1156 = /dll\\reflective_dll\./ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1157 = /dll_hijack_hunter/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1158 = /DLL_Imports_BOF/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1159 = /DLL_TO_HIJACK_WIN10/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1160 = /DLL\-Hijack\-Search\-Order\-BOF/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1161 = /dllinject\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1162 = /dllload\s/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1163 = /dns_beacon_beacon/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1164 = /dns_beacon_dns_idle/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1165 = /dns_beacon_dns_sleep/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1166 = /dns_beacon_dns_stager_prepend/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1167 = /dns_beacon_dns_stager_subhost/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1168 = /dns_beacon_dns_ttl/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1169 = /dns_beacon_get_A/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1170 = /dns_beacon_get_TXT/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1171 = /dns_beacon_maxdns/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1172 = /dns_beacon_ns_response/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1173 = /dns_beacon_put_metadata/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1174 = /dns_beacon_put_output/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1175 = /dns_redir\.sh\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1176 = /dns_stager_prepend/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1177 = /dns_stager_prepend/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1178 = /\'dns_stager_prepend\'/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1179 = /dns_stager_subhost/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1180 = /dns_stager_subhost/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1181 = /\'dns_stager_subhost\'/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1182 = /dns\-beacon\s/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1183 = /dnspayload\.bin/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1184 = /do_attack\(/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string1185 = /Doge\-Loader.*xor\.go/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1186 = /douknowwhoami\?d/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1187 = /dr0op\/CrossNet/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1188 = /DReverseProxy\.git/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1189 = /DReverseServer\.go/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1190 = /drop_malleable_unknown_/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1191 = /drop_malleable_with_invalid_/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1192 = /drop_malleable_without_/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1193 = /dropper32\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1194 = /dropper64\.exe/ nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string1195 = /dtmsecurity\/bof_helper/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1196 = /Dumpert\.bin/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1197 = /Dumpert\.exe/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1198 = /Dumpert\-Aggressor/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1199 = /DumpProcessByName/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1200 = /DumpShellcode\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1201 = /dumpXor\.exe\s/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1202 = /EasyPersistent\.cna/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1203 = /elevate\sjuicypotato\s/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1204 = /elevate\sPrintspoofer/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1205 = /elevate\ssvc\-exe\s/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1206 = /ELFLoader\.c/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1207 = /ELFLoader\.h/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1208 = /ELFLoader\.out/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1209 = /empire\sAttackServers/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1210 = /EncodeGroup\/AggressiveProxy/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1211 = /EncodeGroup\/UAC\-SilentClean/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1212 = /encrypt\/encryptFile\.go/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1213 = /encrypt\/encryptUrl\.go/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1214 = /EncryptShellcode\(/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1215 = /engjibo\/NetUser/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string1216 = /EnumCLR\.exe/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1217 = /Erebus\/.*spacerunner/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1218 = /EspressoCake\/PPLDump_BOF/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1219 = /EventAggregation\.dll\.bak/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1220 = /eventspy\.cna/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1221 = /EventSub\-Aggressor\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1222 = /EventViewerUAC\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1223 = /EventViewerUAC\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1224 = /EventViewerUAC\.x64/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1225 = /EventViewerUAC\.x86/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1226 = /EventViewerUAC_BOF/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1227 = /eventvwr_elevator/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1228 = /EVUAC\s.*\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1229 = /ewby\/Mockingjay_BOF/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1230 = /example\-bof\.sln/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1231 = /execmethod.*PowerPick/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1232 = /execmethod.*PowerShell/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1233 = /execute_bof\s/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1234 = /execute\-assembly\s.*\.exe\s/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1235 = /executepersistence/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1236 = /Export\-PowerViewCSV/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1237 = /extract_reflective_loader/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1238 = /Fiesta\sExploit\sKit/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1239 = /FileControler\/FileControler_x64\.dll/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1240 = /FileControler\/FileControler_x86\.dll/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1241 = /find_payload\(/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1242 = /findgpocomputeradmin/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1243 = /Find\-GPOComputerAdmin/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1244 = /Find\-InterestingDomainAcl/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1245 = /findinterestingdomainsharefile/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1246 = /Find\-InterestingDomainShareFile/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1247 = /findlocaladminaccess/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1248 = /findlocaladminaccess/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1249 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1250 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1251 = /FindModule\s.*\.dll/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1252 = /FindObjects\-BOF/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1253 = /FindProcessTokenAndDuplicate/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1254 = /FindProcHandle\s.*lsass/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1255 = /Firewall_Walker_BOF/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1256 = /fishing_with_hollowing/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1257 = /foreign_access\.cna/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1258 = /foreign_lsass\s.*\s/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1259 = /foreign_lsass\.c/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1260 = /foreign_lsass\.x64/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1261 = /foreign_lsass\.x86/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1262 = /\-\-format\-string\sziiiiizzzb\s.*\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1263 = /\-\-format\-string\sziiiiizzzib\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1264 = /fucksetuptools/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string1265 = /FuckThatPacker\./ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1266 = /FunnyWolf\/pystinger/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1267 = /fw_walk\sdisable/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1268 = /G0ldenGunSec\/GetWebDAVStatus/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1269 = /GadgetToJScript\.exe\s\-a\s/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1270 = /Gality369\/CS\-Loader/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1271 = /gather\/keylogger/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1272 = /geacon.*\/cmd\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1273 = /genCrossC2\./ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1274 = /generate_beacon/ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1275 = /generate\-rotating\-beacon\./ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1276 = /GeorgePatsias\/ScareCrow/ nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string1277 = /get_BeaconHealthCheck_settings/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1278 = /get_dns_dnsidle/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1279 = /get_dns_sleep/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1280 = /get_password_policy\.x64\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1281 = /get_password_policy\.x86\./ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1282 = /get_post_ex_pipename_list/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1283 = /get_post_ex_spawnto_x/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1284 = /get_process_inject_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1285 = /get_process_inject_bof_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1286 = /get_process_inject_execute/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1287 = /get_stage_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1288 = /get_stage_magic_mz_64/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1289 = /get_stage_magic_mz_86/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1290 = /get_stage_magic_pe/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1291 = /get_virtual_Hook_address/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1292 = /getAggressorClient/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1293 = /Get\-BeaconAPI/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1294 = /Get\-CachedRDPConnection/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1295 = /getCrossC2Beacon/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1296 = /getCrossC2Site/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1297 = /getdomainspnticket/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1298 = /Get\-DomainSPNTicket/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1299 = /getexploitablesystem/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1300 = /Get\-ExploitableSystem/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1301 = /GetHijackableDllName/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1302 = /GetNTLMChallengeBase64/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1303 = /GetShellcode\(/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1304 = /GetWebDAVStatus\.csproj/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1305 = /GetWebDAVStatus\.sln/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1306 = /GetWebDAVStatus_DotNet/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1307 = /GetWebDAVStatus_x64\.o/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1308 = /getwmiregcachedrdpconnection/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1309 = /Get\-WMIRegCachedRDPConnection/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1310 = /getwmireglastloggedon/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1311 = /Get\-WMIRegLastLoggedOn/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1312 = /gexplorer\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1313 = /GhostPack\/Koh/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1314 = /github.*\/MoveKit\.git/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1315 = /github\.com\/k8gege/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1316 = /github\.com\/rasta\-mouse\// nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1317 = /github\.com\/SpiderLabs\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1318 = /gloxec\/CrossC2/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1319 = /go_shellcode_encode\.py/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1320 = /go\-shellcode\.py/ nocase ascii wide
        // Description: generate shellcode
        // Reference: https://github.com/fcre1938/goShellCodeByPassVT
        $string1321 = /goShellCodeByPassVT/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1322 = /hackbrowersdata\.cna/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1323 = /hack\-browser\-data\// nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1324 = /handlekatz\.x64\./ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1325 = /handlekatz_bof\./ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1326 = /Hangingsword\/HouQing/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1327 = /hd\-launch\-cmd\s/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1328 = /headers\/exploit\.h/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1329 = /headers\/HandleKatz\.h/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1330 = /Henkru\/cs\-token\-vault/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1331 = /Hidden\.Desktop\.mp4/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1332 = /HiddenDesktop\s.*\s/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1333 = /HiddenDesktop\./ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1334 = /HiddenDesktop\.x64\.bin/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1335 = /HiddenDesktop\.x86\.bin/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1336 = /HiddenDesktop\.zip/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1337 = /hijack_hunter\s/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1338 = /hijack_remote_thread/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1339 = /HiveJack\-Console\.exe/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string1340 = /hollow\s.*\.exe\s.*\.bin/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1341 = /hollower\.Hollow\(/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1342 = /houqingv1\.0\.zip/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1343 = /html\/js\/beacons\.js/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1344 = /http.*\/zha0gongz1/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1345 = /http.*:3200\/manjusaka/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1346 = /http.*:801\/bq1iFEP2/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1347 = /http:\/\/127\.0\.0\.1:8000\/1\.jpg/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1348 = /http_stager_client_header/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1349 = /http_stager_server_append/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1350 = /http_stager_server_header/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1351 = /http_stager_server_prepend/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1352 = /http_stager_uri_x64/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1353 = /http_stager_uri_x86/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1354 = /http1\.x64\.bin/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1355 = /http1\.x64\.dll/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1356 = /httpattack\.py/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1357 = /httppayload\.bin/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1358 = /http\-redwarden/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1359 = /httprelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1360 = /httprelayserver\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1361 = /\'http\-stager\'/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1362 = /HVNC\sServer\.exe/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1363 = /HVNC\\\sServer/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string1364 = /IcebreakerSecurity\/DelegationBOF/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1365 = /IcebreakerSecurity\/PersistBOF/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1366 = /imapattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1367 = /imaprelayclient\.py/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1368 = /impacket\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1369 = /ImpersonateLocalService/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1370 = /import\spe\.OBJExecutable/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1371 = /include\sbeacon\.h/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1372 = /include\sinjection\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1373 = /inject\-amsiBypass\s/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1374 = /inject\-amsiBypass\./ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1375 = /inject\-assembly\s/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1376 = /inject\-assembly\.cna/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1377 = /injectassembly\.x64\.bin/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1378 = /injectassembly\.x64\.o/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1379 = /injectEtwBypass/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1380 = /InjectShellcode/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1381 = /inline\-execute\s/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1382 = /inline\-execute.*whereami\.x64/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1383 = /InlineExecute\-Assembly/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string1384 = /InlineWhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string1385 = /InlineWhispers2/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1386 = /install\simpacket/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1387 = /InvokeBloodHound/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1388 = /Invoke\-Bof\s/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1389 = /Invoke\-Bof\.ps1/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1390 = /invokechecklocaladminaccess/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1391 = /Invoke\-CheckLocalAdminAccess/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1392 = /invokeenumeratelocaladmin/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1393 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1394 = /Invoke\-EnvBypass\./ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1395 = /Invoke\-EventVwrBypass/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1396 = /invokefilefinder/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1397 = /Invoke\-FileFinder/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string1398 = /Invoke\-HostEnum\s\-/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1399 = /invokekerberoast/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1400 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1401 = /Invoke\-Phant0m/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1402 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1403 = /invokeprocesshunter/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1404 = /Invoke\-ProcessHunter/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1405 = /invokereverttoself/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1406 = /Invoke\-RevertToSelf/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1407 = /invokesharefinder/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1408 = /Invoke\-ShareFinder/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1409 = /invokestealthuserhunter/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1410 = /Invoke\-StealthUserHunter/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1411 = /invokeuserhunter/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1412 = /Invoke\-UserHunter/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1413 = /Invoke\-WScriptBypassUAC/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1414 = /jas502n\/bypassAV/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1415 = /java\s\-jar\sBeaconTool\.jar/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1416 = /Job\skilled\sand\sconsole\sdrained/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1417 = /jquery\-c2\..*\.profile/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1418 = /jump\spsexec_psh/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1419 = /jump\spsexec64/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1420 = /jump\swinrm\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1421 = /jump\swinrm/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1422 = /jump\-exec\sscshell/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1423 = /K8_CS_.*\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1424 = /k8gege\.org\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1425 = /k8gege\/Ladon/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1426 = /K8Ladon\.sln/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1427 = /KaliLadon\./ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1428 = /KBDPAYLOAD\.dll/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1429 = /kdstab\s.*\s\/CHECK/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1430 = /kdstab\s.*\s\/CLOSE/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1431 = /kdstab\s.*\s\/DRIVER/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1432 = /kdstab\s.*\s\/KILL/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1433 = /kdstab\s.*\s\/LIST/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1434 = /kdstab\s.*\s\/NAME/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1435 = /kdstab\s.*\s\/PID/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1436 = /kdstab\s.*\s\/SERVICE/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1437 = /kdstab\s.*\s\/STRIP/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1438 = /kdstab\s.*\s\/UNLOAD/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1439 = /kdstab\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1440 = /kerberos.*\.kirbi/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1441 = /kernelcallbacktable\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1442 = /kernelcallbacktable\.x64/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1443 = /kernelcallbacktable\.x86/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1444 = /kernelcallbacktable\.x86/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1445 = /KernelMii\.cna/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1446 = /KernelMii\.x64\.exe/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1447 = /KernelMii\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1448 = /KernelMii\.x86\.exe/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1449 = /KernelMii\.x86\.o/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1450 = /killdefender\scheck/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1451 = /killdefender\skill/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1452 = /KillDefender\.x64/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1453 = /KillDefender\.x64\./ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1454 = /KillDefender_BOF/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1455 = /killdefender_bof/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1456 = /koh\sfilter\sadd\sSID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1457 = /koh\sfilter\slist/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1458 = /koh\sfilter\sremove\sSID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1459 = /koh\sfilter\sreset/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1460 = /koh\sgroups\sLUID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1461 = /koh\simpersonate\sLUID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1462 = /koh\srelease\sall/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1463 = /koh\srelease\sLUID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1464 = /Koh\.exe\scapture/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1465 = /Koh\.exe\slist/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1466 = /Koh\.exe\smonitor/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1467 = /krb5\/kerberosv5\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1468 = /krbcredccache\.py/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string1469 = /kyleavery\/AceLdr/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1470 = /kyleavery\/inject\-assembly/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1471 = /Ladon\s.*\sAllScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1472 = /Ladon\s.*\sCiscoScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1473 = /Ladon\s.*\sOnlineIP/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1474 = /Ladon\s.*\sOnlinePC/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1475 = /Ladon\s.*\sOsScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1476 = /Ladon\s.*\sOxidScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1477 = /Ladon\s.*\.txt\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1478 = /Ladon\s.*DeBase64/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1479 = /Ladon\s.*FtpScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1480 = /Ladon\s.*LdapScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1481 = /Ladon\s.*SMBGhost/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1482 = /Ladon\s.*SmbHashScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1483 = /Ladon\s.*SmbScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1484 = /Ladon\s.*SshScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1485 = /Ladon\s.*TomcatScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1486 = /Ladon\s.*VncScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1487 = /Ladon\s.*WebScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1488 = /Ladon\s.*WinrmScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1489 = /Ladon\s.*WmiHashScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1490 = /Ladon\s.*WmiScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1491 = /Ladon\sActiveAdmin/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1492 = /Ladon\sActiveGuest/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1493 = /Ladon\sAdiDnsDump\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1494 = /Ladon\sat\sc:/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1495 = /Ladon\sAtExec/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1496 = /Ladon\sAutoRun/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1497 = /Ladon\sBadPotato/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1498 = /Ladon\sBypassUAC/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1499 = /Ladon\sCheckDoor/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1500 = /Ladon\sClslog/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1501 = /Ladon\sCmdDll\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1502 = /Ladon\scmdline/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1503 = /Ladon\sCVE\-/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1504 = /Ladon\sDirList/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1505 = /Ladon\sDraytekExp/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1506 = /Ladon\sDumpLsass/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1507 = /Ladon\sEnableDotNet/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1508 = /Ladon\sEnumProcess/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1509 = /Ladon\sEnumShare/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1510 = /Ladon\sExploit/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1511 = /Ladon\sFindIP\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1512 = /Ladon\sFirefoxCookie/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1513 = /Ladon\sFirefoxHistory/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1514 = /Ladon\sFirefoxPwd/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1515 = /Ladon\sForExec\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1516 = /Ladon\sFtpDownLoad\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1517 = /Ladon\sFtpServer\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1518 = /Ladon\sGetDomainIP/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1519 = /Ladon\sgethtml\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1520 = /Ladon\sGetPipe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1521 = /Ladon\sGetSystem/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1522 = /Ladon\sIISdoor/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1523 = /Ladon\sIISpwd/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1524 = /Ladon\sMssqlCmd\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1525 = /Ladon\snetsh\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1526 = /Ladon\snoping\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1527 = /Ladon\sOpen3389/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1528 = /Ladon\sPowerCat\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1529 = /Ladon\sPrintNightmare/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1530 = /Ladon\spsexec/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1531 = /Ladon\sQueryAdmin/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1532 = /Ladon\sRdpHijack/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1533 = /Ladon\sReadFile\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1534 = /Ladon\sRegAuto/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1535 = /Ladon\sReverseHttps/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1536 = /Ladon\sReverseTcp\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1537 = /Ladon\sRevShell\-/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1538 = /Ladon\sRunas/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1539 = /Ladon\sRunPS\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1540 = /Ladon\ssc\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1541 = /Ladon\sSetSignAuth/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1542 = /Ladon\sSmbExec\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1543 = /Ladon\sSniffer/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1544 = /Ladon\sSshExec\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1545 = /Ladon\sSweetPotato/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1546 = /Ladon\sTcpServer\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1547 = /Ladon\sUdpServer/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1548 = /Ladon\sWebShell/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1549 = /Ladon\swhoami/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1550 = /Ladon\sWifiPwd/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1551 = /Ladon\swmiexec/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1552 = /Ladon\sWmiExec2\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1553 = /Ladon\sXshellPwd/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1554 = /Ladon\sZeroLogon/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1555 = /Ladon40\sBypassUAC/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1556 = /Ladon911.*\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1557 = /Ladon911\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1558 = /Ladon911_.*\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1559 = /LadonExp\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1560 = /LadonGUI\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1561 = /LadonLib\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1562 = /LadonStudy\.exe/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1563 = /lastpass\.x86/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1564 = /lastpass\/process_lp_files\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1565 = /ldap_shell\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1566 = /ldapattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1567 = /ldaprelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1568 = /LdapSignCheck\.exe/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1569 = /LdapSignCheck\.Natives/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1570 = /LdapSignCheck\.sln/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1571 = /ldapsigncheck\.x64\./ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1572 = /ldapsigncheck\.x86\./ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1573 = /LetMeOutSharp\./ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1574 = /libs\/bofalloc/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1575 = /libs\/bofentry/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1576 = /libs\/bofhelper/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1577 = /LiquidSnake\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1578 = /llsrpc_\#\#/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1579 = /load\saggressor\sscript/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string1580 = /load_sc\.exe\s.*\.bin/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1581 = /Load\-BeaconParameters/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1582 = /Load\-Bof\(/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1583 = /loader\/loader\/loader\.c/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1584 = /logToBeaconLog/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1585 = /lsarpc_\#\#/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1586 = /Magnitude\sExploit\sKit/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1587 = /main_air_service\-probes\.go/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1588 = /main_pro_service\-probes\.go/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1589 = /makebof\.bat/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string1590 = /Malleable\sC2\sFiles/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1591 = /Malleable\sPE\/Stage/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1592 = /malleable_redirector\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1593 = /malleable_redirector_hidden_api_endpoint/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1594 = /Malleable\-C2\-Profiles/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1595 = /Malleable\-C2\-Randomizer/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1596 = /Malleable\-C2\-Randomizer/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1597 = /malleable\-redirector\-config/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string1598 = /mandllinject\s/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1599 = /mdsecactivebreach\/CACTUSTORCH/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1600 = /med0x2e\/SigFlip/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1601 = /memreader\s.*access_token/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1602 = /MemReader_BoF\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1603 = /meterpreter\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1604 = /metsrv\.dll/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1605 = /mgeeky\/RedWarden/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1606 = /mimipenguin\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1607 = /mimipenguin\.so/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1608 = /mimipenguin_x32\.so/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1609 = /minidump_add_memory_block/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1610 = /minidump_add_memory64_block/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1611 = /minidumpwritedump/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1612 = /MiniDumpWriteDump/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1613 = /miscbackdoorlnkhelp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1614 = /Mockingjay_BOF\.sln/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1615 = /Mockingjay_BOF\-main/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1616 = /mojo_\#\#/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1617 = /moonD4rk\/HackBrowserData/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1618 = /MoveKit\-master\.zip/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1619 = /move\-msbuild\s.*\shttp\smove\.csproj/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1620 = /move\-pre\-custom\-file\s.*\.exe\s/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string1621 = /msfvemonpayload/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1622 = /mssqlattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1623 = /mssqlrelayclient\.py/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1624 = /my_dump_my_pe/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1625 = /needle_sift\.x64/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1626 = /needlesift\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1627 = /netero1010\/Quser\-BOF/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1628 = /netero1010\/ServiceMove\-BOF/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1629 = /netlogon_\#\#/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1630 = /netuser_enum/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1631 = /netview_enum/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1632 = /NoApiUser\.exe/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1633 = /normal\/randomized\.profile/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1634 = /ntcreatethread\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1635 = /ntcreatethread\.x86/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1636 = /oab\-parse\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1637 = /obscuritylabs\/ase:latest/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1638 = /obscuritylabs\/RAI\// nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1639 = /Octoberfest7\/KDStab/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1640 = /OG\-Sadpanda\/SharpCat/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string1641 = /OG\-Sadpanda\/SharpSword/ nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string1642 = /OG\-Sadpanda\/SharpZippo/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1643 = /On_Demand_C2\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1644 = /On\-Demand_C2_BOF\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1645 = /OnDemandC2Class\.cs/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1646 = /openBeaconBrowser/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1647 = /openBeaconBrowser/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1648 = /openBeaconConsole/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1649 = /openBeaconConsole/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1650 = /openBypassUACDialog/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1651 = /openBypassUACDialog/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1652 = /openGoldenTicketDialog/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1653 = /openKeystrokeBrowser/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1654 = /openPayloadGenerator/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1655 = /openPayloadGeneratorDialog/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1656 = /openPayloadHelper/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1657 = /openPortScanner/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1658 = /openPortScanner/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1659 = /openSpearPhishDialog/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1660 = /openWindowsExecutableStage/ nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string1661 = /optiv\/Registry\-Recon/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1662 = /optiv\/ScareCrow/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1663 = /Outflank\-Dumpert\./ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1664 = /outflanknl\/Recon\-AD/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string1665 = /outflanknl\/Spray\-AD/ nocase ascii wide
        // Description: s
        // Reference: https://github.com/outflanknl/WdToggle
        $string1666 = /outflanknl\/WdToggle/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1667 = /Outflank\-Recon\-AD/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1668 = /output\/html\/data\/beacons\.json/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1669 = /output\/payloads\// nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1670 = /parse_aggressor_properties/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1671 = /parse_shellcode/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1672 = /patchAmsiOpenSession/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1673 = /payload_bootstrap_hint/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1674 = /payload_local/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1675 = /payload_scripts\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1676 = /payload_scripts\/sleepmask/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1677 = /payload_section\.cpp/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1678 = /payload_section\.hpp/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1679 = /payloadgenerator\.py/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1680 = /PersistBOF\.cna/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1681 = /PersistenceBOF\.c/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1682 = /PersistenceBOF\.exe/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1683 = /persist\-ice\-junction\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1684 = /persist\-ice\-monitor\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1685 = /persist\-ice\-shortcut\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1686 = /persist\-ice\-time\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1687 = /persist\-ice\-xll\.o/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1688 = /Phant0m_cobaltstrike/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1689 = /\'pipename_stager\'/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1690 = /Pitty\sTiger\sRAT/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1691 = /\-pk8gege\.org/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1692 = /pkexec64\.tar\.gz/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1693 = /plug_getpass_nps\.dll/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1694 = /plug_katz_nps\.exe/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1695 = /plug_qvte_nps\.exe/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1696 = /PortBender\sbackdoor/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1697 = /PortBender\sredirect/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1698 = /PortBender\.cna/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1699 = /PortBender\.cpp/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1700 = /portbender\.dll/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1701 = /PortBender\.exe/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1702 = /PortBender\.h/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1703 = /PortBender\.sln/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1704 = /PortBender\.zip/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1705 = /portscan_result\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1706 = /portscan386\s/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1707 = /portscan64\s/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1708 = /post_ex_amsi_disable/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1709 = /post_ex_keylogger/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1710 = /post_ex_obfuscate/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1711 = /Post_EX_Process_Name/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1712 = /post_ex_smartinject/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1713 = /post_ex_spawnto_x64/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1714 = /post_ex_spawnto_x86/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1715 = /powershell_encode_oneliner/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1716 = /powershell_encode_oneliner/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1717 = /powershell_encode_stager/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1718 = /powershell_encode_stager/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1719 = /powershell\-import\s.*\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1720 = /PowerView3\-Aggressor/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1721 = /ppenum\.c/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1722 = /ppenum\.exe/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1723 = /ppenum\.x64\./ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1724 = /ppenum\.x86\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1725 = /ppl_dump\.x64/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1726 = /ppldump\s/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1727 = /PPLDump_BOF\./ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1728 = /pplfault\.cna/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1729 = /PPLFaultDumpBOF/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1730 = /PPLFaultPayload\.dll/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1731 = /PPLFaultTemp/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1732 = /praetorian\.antihacker/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1733 = /praetorian\-inc\/PortBender/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1734 = /prepareResponseForHiddenAPICall/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1735 = /PrintSpoofer\-/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1736 = /PrintSpoofer\./ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1737 = /process_imports\.cna/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1738 = /process_imports\.x64/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1739 = /process_imports_api\s.*\.exe/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1740 = /process_inject_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1741 = /process_inject_bof_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1742 = /process_inject_bof_reuse_memory/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1743 = /process_inject_execute/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1744 = /process_inject_min_alloc/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1745 = /process_inject_startrwx/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1746 = /Process_Inject_Struct/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1747 = /process_inject_transform_x/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1748 = /process_inject_userwx/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1749 = /process_protection_enum\s/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1750 = /process_protection_enum.*\.dmp/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1751 = /process_protection_enum\./ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1752 = /Process_Protection_Level_BOF\./ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1753 = /Process_Protection_Level_BOF\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1754 = /ProcessDestroy\.x64/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1755 = /ProcessDestroy\.x64\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1756 = /ProcessDestroy\.x86/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1757 = /ProcessDestroy\.x86\./ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1758 = /process\-inject\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1759 = /processinject_min_alloc/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1760 = /ProgIDsUACBypass\./ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1761 = /Proxy\sShellcode\sHandler/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1762 = /proxychains.*scshell/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1763 = /proxyshellcodeurl/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1764 = /PSconfusion\.py/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1765 = /PSEXEC_PSH\s/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/pureqh/bypassAV
        $string1766 = /pureqh\/bypassAV/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1767 = /pwn1sher\/CS\-BOFs/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1768 = /pycobalt\./ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1769 = /pycobalt\/aggressor/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1770 = /pycobalt_debug_on/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1771 = /pycobalt_path/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1772 = /pycobalt_python/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1773 = /pycobalt_timeout/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1774 = /pyMalleableC2/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1775 = /pystinger_for_darkshadow/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1776 = /python\sscshell/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1777 = /python2\?\?\/generator\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1778 = /python2\?\?\/PyLoader\.py/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1779 = /python3\sscshell/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1780 = /python3\?\?\/generator\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1781 = /python3\?\?\/PyLoader\.py/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1782 = /QUAPCInjectAsSystem/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1783 = /QUAPCInjectElevated/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1784 = /QUAPCInjectFakecmd/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1785 = /QUAPCInjectFakecmd/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1786 = /QUAPCInjectWithoutPid/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1787 = /quser\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1788 = /quser\.x86\.o/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1789 = /QXh4OEF4eDhBeHg4QXh4OA\=\=/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1790 = /RAI\/ase_docker/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1791 = /rai\-attack\-servers\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1792 = /rai\-redirector\-dns/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1793 = /rai\-redirector\-http/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1794 = /random_c2_profile/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1795 = /random_c2profile\./ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1796 = /random_user_agent\.params/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1797 = /random_user_agent\.user_agent/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1798 = /rasta\-mouse\/PPEnum/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1799 = /rasta\-mouse\/TikiTorch/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1800 = /rdi_net_user\.cpp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1801 = /rdphijack\.x64/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1802 = /rdphijack\.x86/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1803 = /RDPHijack\-BOF/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1804 = /RdpThief\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1805 = /read_cs_teamserver/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1806 = /Recon\-AD\-.*\.dll/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1807 = /Recon\-AD\-.*\.sln/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1808 = /Recon\-AD\-.*\.vcxproj/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1809 = /Recon\-AD\-AllLocalGroups/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1810 = /Recon\-AD\-Domain/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1811 = /Recon\-AD\-LocalGroups/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1812 = /Recon\-AD\-SPNs/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1813 = /Recon\-AD\-Users\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1814 = /redelk_backend_name_c2/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1815 = /redelk_backend_name_decoy/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1816 = /Red\-Team\-Infrastructure\-Wiki\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1817 = /RedWarden\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1818 = /RedWarden\.test/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1819 = /redwarden_access\.log/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1820 = /redwarden_redirector\.log/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1821 = /reflective_dll\.dll/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1822 = /reflective_dll\.x64\.dll/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1823 = /ReflectiveDll\.x64\.dll/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1824 = /ReflectiveDll\.x86\.dll/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1825 = /Reflective\-HackBrowserData/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1826 = /Remote\/lastpass\/lastpass\.x86\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1827 = /Remote\/setuserpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1828 = /Remote\/shspawnas/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1829 = /Remote\/suspendresume\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1830 = /remote\-exec\s.*jump\s/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1831 = /remotereg\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1832 = /replace_key_iv_shellcode/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1833 = /RiccardoAncarani\/BOFs/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1834 = /RiccardoAncarani\/LiquidSnake/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string1835 = /RiccardoAncarani\/TaskShell/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1836 = /rkervella\/CarbonMonoxide/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1837 = /rookuu\/BOFs\// nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1838 = /rpcattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1839 = /rpcrelayclient\.py/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1840 = /rsmudge\/ElevateKit/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1841 = /runasadmin\suac\-cmstplua/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1842 = /runasadmin\suac\-token\-duplication/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1843 = /RunOF\.exe\s\-/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1844 = /RunOF\.Internals/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1845 = /rustbof\.cna/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1846 = /rvrsh3ll\/BOF_Collection/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1847 = /rxwx\/cs\-rdll\-ipc\-example/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1848 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1849 = /SamAdduser\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1850 = /samr_\#\#/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1851 = /ScareCrow.*\s\-encryptionmode\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1852 = /ScareCrow.*\s\-Evasion/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1853 = /ScareCrow.*\s\-Exec/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1854 = /ScareCrow.*\s\-injection/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1855 = /ScareCrow.*\s\-Loader\s.*\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1856 = /ScareCrow.*\s\-noamsi/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1857 = /ScareCrow.*\s\-noetw/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1858 = /ScareCrow.*\s\-obfu/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1859 = /ScareCrow.*_darwin_amd64/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1860 = /ScareCrow.*_windows_amd64\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1861 = /ScareCrow.*KnownDLL/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1862 = /ScareCrow.*ProcessInjection/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1863 = /ScareCrow\.cna/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1864 = /ScareCrow\/Cryptor/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1865 = /ScareCrow\/limelighter/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1866 = /ScareCrow\/Loader/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1867 = /ScareCrow\/Utils/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1868 = /schshell\.cna/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1869 = /schtask_callback/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1870 = /schtasks_elevator/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1871 = /schtasks_exploit\s/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1872 = /ScRunBase32\.exe/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1873 = /ScRunBase32\.py/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1874 = /ScRunBase64\.exe/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1875 = /ScRunBase64\.py/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1876 = /scshell.*XblAuthManager/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1877 = /SCShell\.exe/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1878 = /scshell\.py/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1879 = /scshellbof\.c/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1880 = /scshellbof\.o/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1881 = /scshellbofx64/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1882 = /searchsploit_rc/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1883 = /Seatbelt\.exe/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1884 = /sec\-inject\s/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1885 = /secinject\.cna/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1886 = /secinject\.git/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1887 = /secinject\.x64/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1888 = /secinject\.x86/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1889 = /secinject\/src/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1890 = /secretsdump\..*\.pyc/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1891 = /secretsdump\.py/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1892 = /sec\-shinject\s/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1893 = /self_delete\.x64\.o/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1894 = /Self_Deletion_BOF/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1895 = /send_shellcode_via_pipe/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1896 = /send_shellcode_via_pipe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1897 = /serverscan\.linux\.elf/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1898 = /serverscan\.linux\.so/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1899 = /serverScan\.win\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1900 = /serverscan_386\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1901 = /ServerScan_Air_.*\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1902 = /ServerScan_Air_.*_amd64/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1903 = /ServerScan_Air_.*_i386/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1904 = /serverscan_air\-probes\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1905 = /serverscan_amd64\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1906 = /ServerScan_Pro_.*\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1907 = /ServerScan_Pro_.*_amd64/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1908 = /ServerScan_Pro_.*_i386/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1909 = /serverscan64\s/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1910 = /serverscan64\s.*tcp/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1911 = /serverscan86\s/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1912 = /servicemove.*hid\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1913 = /set\shosts_stage/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1914 = /set\skeylogger/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1915 = /set\sobfuscate\s/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1916 = /set\spipename\s/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1917 = /set\ssmartinject/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1918 = /set\suserwx/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1919 = /setc_webshell/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1920 = /setLoaderFlagZero/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1921 = /setthreadcontext\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1922 = /setthreadcontext\.x86/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1923 = /setup_obfuscate_xor_key/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1924 = /setup_reflective_loader/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1925 = /seventeenman\/CallBackDump/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1926 = /ShadowUser\/scvhost\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1927 = /Sharp\sCompile/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string1928 = /SharpCalendar\.exe/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1929 = /SharpCat\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1930 = /sharpcompile.*\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1931 = /sharpCompileHandler/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1932 = /SharpCompileServer/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1933 = /SharpCompileServer\.exe/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1934 = /SharpCradle.*logonpasswords/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1935 = /SharpCradle\.exe/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string1936 = /SharpEventLoader/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string1937 = /SharpEventPersist/ nocase ascii wide
        // Description: Read Excel Spreadsheets (XLS/XLSX) using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpExcelibur
        $string1938 = /SharpExcelibur/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1939 = /sharp\-exec\s/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1940 = /sharp\-fexec\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1941 = /SharpGen\.dll/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1942 = /sharpgen\.enable_cache/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1943 = /sharpgen\.py/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1944 = /sharpgen\.set_location/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1945 = /Sharp\-HackBrowserData/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1946 = /SharpHound\.cna/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1947 = /SharpHound\.exe/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1948 = /SharpHound\.ps1/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1949 = /Sharphound2\./ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1950 = /Sharphound\-Aggressor/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1951 = /SharpSCShell/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1952 = /SharpSploitConsole_x/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1953 = /SharpStay\.exe/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string1954 = /SharpSword\.exe/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1955 = /SharpZeroLogon/ nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string1956 = /SharpZippo\.exe/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1957 = /shell\.exe\s\-s\spayload\.txt/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1958 = /Shellcode_encryption\.exe/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string1959 = /shellcode_generator\./ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string1960 = /shellcode_generator_help\.html/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1961 = /ShellCode_Loader\.py/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string1962 = /shellcode20\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string1963 = /shellcode30\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string1964 = /shellcode35\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string1965 = /shellcode40\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1966 = /shspawn\sx64\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1967 = /shspawn\sx86\s/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1968 = /SigFlip\.exe\s\-/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1969 = /SigFlip\.WinTrustData/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1970 = /SigInject\s.*\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1971 = /Sigloader\s.*\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1972 = /SigLoader\/sigloader\.c/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1973 = /sigwhatever\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string1974 = /Silent\sLsass\sDump/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string1975 = /silentLsassDump/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1976 = /\-Situational\-Awareness\-BOF/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1977 = /sleep_python_bridge\.sleepy/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1978 = /sleep_python_bridge\.striker/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1979 = /sleepmask\.x64\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1980 = /sleepmask\.x86\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1981 = /sleepmask_pivot\.x64\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1982 = /sleepmask_pivot\.x86\.o/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1983 = /smb_pipename_stager/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1984 = /smbattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1985 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1986 = /smbrelayserver\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1987 = /smtprelayclient\.py/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string1988 = /socky\swhoami/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1989 = /SourcePoint.*Loader\.go/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1990 = /source\-teamserver\.sh/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1991 = /spawn\/runshellcode/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1992 = /SpawnTheThing\(/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1993 = /spawnto\s.*\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1994 = /\'spawnto_x64\'/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1995 = /\'spawnto_x86\'/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1996 = /spoolss_\#\#/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string1997 = /spoolsystem\sinject/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string1998 = /spoolsystem\sspawn/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string1999 = /spoolsystem\.cna/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2000 = /SpoolTrigger\.x64\.dl/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2001 = /SpoolTrigger\.x64\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2002 = /SpoolTrigger\.x86\.dl/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2003 = /SpoolTrigger\.x86\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2004 = /SpoolTrigger\\SpoolTrigger\./ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2005 = /Spray\-AD\s/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2006 = /Spray\-AD\.cna/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2007 = /Spray\-AD\.dll/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2008 = /Spray\-AD\.exe/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2009 = /Spray\-AD\.sln/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2010 = /Spray\-AD\\Spray\-AD/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2011 = /src\/Remote\/chromeKey\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2012 = /src\/Remote\/lastpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2013 = /src\/Remote\/sc_config\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2014 = /src\/Remote\/sc_create\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2015 = /src\/Remote\/sc_delete\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2016 = /src\/Remote\/sc_start\// nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2017 = /Src\/Spray\-AD/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2018 = /src\/zerologon\.c/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string2019 = /src\\unhook\.c/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2020 = /srvsvc_\#\#/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2021 = /stage\.obfuscate/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2022 = /stage_smartinject/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2023 = /stage_transform_x64_prepend/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2024 = /stage_transform_x64_strrep1/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2025 = /stage_transform_x86_prepend/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2026 = /stage_transform_x86_strrep1/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string2027 = /stageless\spayload/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2028 = /stager_bind_pipe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2029 = /stager_bind_pipe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2030 = /stager_bind_tcp/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2031 = /stager_bind_tcp/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2032 = /start\sstinger\s/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2033 = /StartProcessFake\(/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2034 = /static_syscalls_apc_spawn\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2035 = /static_syscalls_apc_spawn/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2036 = /static_syscalls_dump/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2037 = /StayKit\.cna/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2038 = /StayKit\.exe/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2039 = /StayKit\.git/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2040 = /steal_token\(/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2041 = /steal_token_access_mask/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2042 = /stinger_client\s\-/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2043 = /stinger_client\.py/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2044 = /stinger_server\.exe/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2045 = /strip_bof\.ps1/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2046 = /strip\-bof\s\-Path\s/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2047 = /suspendresume\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2048 = /suspendresume\.x86\./ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2049 = /SW2_GetSyscallNumber/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2050 = /SW2_HashSyscall/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2051 = /SW2_PopulateSyscallList/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2052 = /SW2_RVA2VA/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2053 = /SwampThing\.exe/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2054 = /SweetPotato\.cna/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2055 = /SweetPotato\.csproj/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2056 = /SweetPotato\.exe/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2057 = /SweetPotato\.ImpersonationToken/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2058 = /SweetPotato\.sln/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2059 = /syscall_disable_priv\s/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2060 = /syscall_enable_priv\s/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2061 = /syscalls\.asm/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2062 = /syscalls_dump\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2063 = /syscalls_inject\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2064 = /syscalls_inject\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2065 = /syscalls_shinject\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2066 = /syscalls_shspawn\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2067 = /syscalls_spawn\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2068 = /syscalls_spawn\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2069 = /syscallsapcspawn\.x64/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2070 = /syscalls\-asm\.h/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2071 = /syscallsdump\.x64/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2072 = /syscallsinject\.x64/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2073 = /syscallsspawn\.x64/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2074 = /SysWhispers\.git\s/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2075 = /syswhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2076 = /syswhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2077 = /SysWhispers2/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2078 = /TailorScan\.exe\s/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2079 = /TailorScan_darwin/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2080 = /TailorScan_freebsd/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2081 = /TailorScan_linux_/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2082 = /TailorScan_netbsd_/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2083 = /TailorScan_openbsd_/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2084 = /TailorScan_windows_.*\.exe/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2085 = /TaskShell\.exe\s.*\s\-b\s.*\.exe/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2086 = /TaskShell\.exe\s.*\s\-s\s.*SYSTEM/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string2087 = /teamserver.*\sno_evasion\.profile/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string2088 = /TeamServer\.prop/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string2089 = /Temp\\dumpert/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string2090 = /test_invoke_bof\.x64\.o/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2091 = /tgtdelegation\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2092 = /tgtdelegation\.cna/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2093 = /tgtdelegation\.x64/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2094 = /tgtdelegation\.x86/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2095 = /tgtParse\.py\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2096 = /third_party\/SharpGen/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2097 = /third\-party.*winvnc.*\.dll/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2098 = /threatexpress.*malleable/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string2099 = /threatexpress\/cs2modrewrite/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2100 = /ticketConverter\.py\s.*\.ccache\s/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string2101 = /tijme\/kernel\-mii/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2102 = /TikiLoader.*Hollower/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2103 = /TikiLoader\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2104 = /TikiLoader\./ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2105 = /TikiLoader\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2106 = /TikiLoader\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2107 = /TikiLoader\.Injector/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2108 = /TikiLoader\\TikiLoader/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2109 = /TikiSpawn\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2110 = /TikiSpawn\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2111 = /TikiSpawn\.ps1/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2112 = /TikiSpawnAs/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2113 = /TikiSpawnAsAdmin/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2114 = /TikiSpawnElevated/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2115 = /TikiSpawnWOppid/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2116 = /TikiSpawnWppid/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2117 = /TikiTorch\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2118 = /TikiVader\./ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2119 = /timwhitez\/Doge\-Loader/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2120 = /Tmprovider\.dll/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2121 = /toggle_privileges\.cna/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2122 = /toggle_privileges_bof\./ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2123 = /Toggle_Token_Privileges_BOF/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2124 = /ToggleWDigest/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string2125 = /TokenStripBOF\/src/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2126 = /token\-vault\ssteal/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2127 = /token\-vault\.cna/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2128 = /token\-vault\.x64\.o/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2129 = /token\-vault\.x86\.o/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string2130 = /trainr3kt\/MemReader_BoF/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string2131 = /trainr3kt\/Readfile_BoF/ nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2132 = /TrustedPath\-UACBypass\-BOF/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2133 = /Tycx2ry\/SweetPotato/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2134 = /Tylous\/SourcePoint/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2135 = /UACBypass\-BOF/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2136 = /uac\-schtasks\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2137 = /uac\-schtasks/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string2138 = /uac\-silentcleanup/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2139 = /uac\-token\-duplication/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2140 = /uhttpsharp\./ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2141 = /uknowsec\/TailorScan/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2142 = /UMJjAiNUUtvNww0lBj9tzWegwphuIn6hNP9eeIDfOrcHJ3nozYFPT\-Jl7WsmbmjZnQXUesoJkcJkpdYEdqgQFE6QZgjWVsLSSDonL28DYDVJ/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2143 = /Un1k0d3r\/SCShell/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string2144 = /ursnif_IcedID\.profile/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2145 = /Visual\-Studio\-BOF\-template/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2146 = /vssenum\.x64\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2147 = /vssenum\.x86\./ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string2148 = /vysecurity\/ANGRYPUPPY/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2149 = /wcfrelayserver\.py/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2150 = /wdigest\!g_fParameter_UseLogonCredential/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2151 = /wdigest\!g_IsCredGuardEnabled/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2152 = /whereami\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2153 = /whereami\.x64/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2154 = /WhoamiGetTokenInfo/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2155 = /wifidump\.cna/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string2156 = /windows\-exploit\-suggester\./ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2157 = /winrmdll\s/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2158 = /winrmdll\./ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2159 = /Winsocky\-main/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string2160 = /WKL\-Sec\/HiddenDesktop/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2161 = /WKL\-Sec\/Winsocky/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2162 = /wkssvc_\#\#/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string2163 = /Wmi_Persistence\.ps1/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2164 = /wmi\-event\-lateral\-movement\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2165 = /WMI\-EventSub\.cpp/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2166 = /wmi\-lateral\-movement\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2167 = /WMI\-ProcessCreate\.cpp/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string2168 = /write_cs_teamserver/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2169 = /WriteAndExecuteShellcode/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string2170 = /WritePayloadDllTransacted/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2171 = /wscript_elevator/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string2172 = /wts_enum_remote_processes/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string2173 = /wumb0\/rust_bof/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string2174 = /xforcered\/CredBandit/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/xforcered/Detect-Hooks
        $string2175 = /xforcered\/Detect\-Hooks/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2176 = /xor\.exe\s.*\.txt/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string2177 = /xor_payload/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2178 = /xpipe\s\\\\/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2179 = /xpipe.*lsass/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2180 = /xpipe\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2181 = /xpipe\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2182 = /xpipe\.o/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string2183 = /YDHCUI\/csload\.net/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string2184 = /YDHCUI\/manjusaka/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string2185 = /youcantpatchthis/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2186 = /ysoserial\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2187 = /YwBhAGwAYwA\=/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2188 = /zerologon\.x64/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2189 = /zerologon\.x86/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2190 = /ZeroLogon\-BOF/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2191 = /zha0gongz1/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2192 = /zha0gongz1\/DesertFox/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2193 = /ziiiiizzzb/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2194 = /ziiiiizzzib/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2195 = /\\\\demoagent_11/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2196 = /\\\\demoagent_22/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2197 = /\\\\DserNamePipe/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2198 = /\\\\f4c3/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2199 = /\\\\f53f/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2200 = /\\\\fullduplex_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2201 = /\\\\interprocess_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2202 = /\\\\lsarpc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2203 = /\\\\mojo_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2204 = /\\\\msagent_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2205 = /\\\\MsFteWds/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2206 = /\\\\msrpc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2207 = /\\\\MSSE\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2208 = /\\\\mypipe\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2209 = /\\\\netlogon_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2210 = /\\\\ntsvcs/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2211 = /\\\\PGMessagePipe/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2212 = /\\\\postex_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2213 = /\\\\postex_ssh_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2214 = /\\\\samr_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2215 = /\\\\scerpc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2216 = /\\\\SearchTextHarvester/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2217 = /\\\\spoolss_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2218 = /\\\\srvsvc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2219 = /\\\\status_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2220 = /\\\\UIA_PIPE/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2221 = /\\\\win\\msrpc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2222 = /\\\\winsock/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2223 = /\\\\Winsock2\\CatalogChangeListener\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2224 = /\\\\wkssvc_/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string2225 = /detect\-hooks/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2226 = /doc\.1a\..*\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2227 = /doc\.4a\..*\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2228 = /doc\.bc\..*\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2229 = /doc\.md\..*\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2230 = /doc\.po\..*\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2231 = /doc\.tx\..*\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2232 = /doc\-stg\-prepend.*\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2233 = /doc\-stg\-sh.*\./ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2234 = /dumpwifi\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2235 = /etw\sstop/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2236 = /EVUAC\s/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2237 = /fw_walk\sdisplay/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2238 = /fw_walk\sstatus/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2239 = /fw_walk\stotal/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2240 = /get\-delegation\s/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2241 = /get\-spns\s/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string2242 = /koh\sexit/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string2243 = /koh\slist/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2244 = /Ladon\s.*\-.*\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2245 = /Ladon\s.*\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2246 = /Ladon\s.*\/.*\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2247 = /Ladon\sMac\s.*\s/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string2248 = /LdapSignCheck\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2249 = /load\s.*\.cna/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string2250 = /make_token\s/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string2251 = /needle_sift\s/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string2252 = /remotereg\s/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2253 = /rev2self/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string2254 = /scrun\.exe\s/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string2255 = /shell\.exe\s\-u\shttp:\/\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2256 = /SigFlip\s.*\.exe/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string2257 = /sleeper\sforce/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string2258 = /sleeper\soff/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string2259 = /sleeper\son/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string2260 = /spawn\s.*\.exe\s.*\.bin/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string2261 = /TokenStrip\s/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2262 = /token\-vault\screate/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2263 = /token\-vault\sremove/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2264 = /token\-vault\sset\s/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2265 = /token\-vault\sshow/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2266 = /token\-vault\suse/ nocase ascii wide

    condition:
        any of them
}