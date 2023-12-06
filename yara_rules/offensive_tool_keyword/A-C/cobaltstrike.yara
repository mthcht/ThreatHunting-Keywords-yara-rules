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
        $string3 = /\s.{0,1000}\/lsass\.o/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string4 = /\s\.beacon_keys\s\-/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string5 = /\s\/NAME:.{0,1000}\s\/KILL/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string6 = /\s\/PID:.{0,1000}\s\/DRIVER:/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string7 = /\s\/PID:.{0,1000}\s\/KILL/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string8 = /\s\/ticket:.{0,1000}\s\/service:.{0,1000}\s\/targetdomain:.{0,1000}\s\/targetdc:/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string9 = /\s\/user:.{0,1000}\s\/password:.{0,1000}\s\/enctype:.{0,1000}\s\/opsec\s\/ptt/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string10 = /\s1\.2\.3\.4:8080/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string11 = /\s4444\smeter/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string12 = /\s4444\sshell/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string13 = /\samsi_disable\s/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string14 = /\sarp\.x64\.o/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string15 = /\s\-\-assemblyargs\sAntiVirus/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string16 = /\s\-\-assemblyargs\sAppLocker/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string17 = /\sbase64_encode_shellcode/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string18 = /\sbeacon\.dll/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string19 = /\sbof_allocator\s/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string20 = /\sbof_reuse_memory\s/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string21 = /\s\-BOFBytes\s/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string22 = /\sBOFNET\s/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string23 = /\sBofRunner\(/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string24 = /\sbuild\sDent\.go/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string25 = /\sbuild_letmeout/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string26 = /\sBypassUac.{0,1000}\.bat/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string27 = /\sBypassUac.{0,1000}\.dll/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string28 = /\sBypassUac.{0,1000}\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string29 = /\s\-c\sCredEnum\.c/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string30 = /\schrome\slogindata\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string31 = /\schrome\smasterkey\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string32 = /\s\-cobalt\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string33 = /\scobaltstrike/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string34 = /\sCoffeeExecuteFunction/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string35 = /\scom\.blackh4t/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string36 = /\sCrossC2\sListener/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string37 = /\sCrossC2\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string38 = /\sCrossC2Kit\s/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string39 = /\sDelegationBOF\.c\s/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string40 = /\sdelegationx64\.o/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string41 = /\sdelegationx86\.o/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string42 = /\sDesertFox\.go/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string43 = /\sdetect\-hooks\.c\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string44 = /\s\-dns_stager_prepend\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string45 = /\s\-dns_stager_subhost\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string46 = /\s\-\-dotnetassembly\s.{0,1000}\s\-\-amsi/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string47 = /\s\-\-dotnetassembly\s.{0,1000}\s\-\-appdomain\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string48 = /\s\-\-dotnetassembly\s.{0,1000}\s\-\-assemblyargs\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string49 = /\s\-\-dotnetassembly\s.{0,1000}\s\-\-mailslot/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string50 = /\s\-\-dotnetassembly\s.{0,1000}\s\-\-pipe\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string51 = /\sDraytekScan/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string52 = /\sdump_memory64/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string53 = /\sedge\slogindata\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string54 = /\sedge\smasterkey\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string55 = /\sEfsPotato/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string56 = /\sexclusion\.c\s\/Fodefender\.o/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string57 = /\s\-FakeCmdLine\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string58 = /\sFileZillaPwd/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string59 = /\sforgeTGT\(/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string60 = /\sFtpSniffer\s/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string61 = /\sgenerate_my_dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string62 = /\sgeneratePayload/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string63 = /\sGetAppLockerPolicies/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string64 = /\sGetLsassPid/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string65 = /\sgophish\-.{0,1000}\.zip/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string66 = /\sHackBrowserData/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string67 = /\s\-hasbootstraphint\s/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string68 = /\sHiddenDesktop\.cna/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string69 = /\shollow\.x64\./ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string70 = /\shostenum\.py\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string71 = /\sHTTPSniffer\s/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string72 = /\s\-i\shavex\.profile\s/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string73 = /\simpacket\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string74 = /\s\-Injector\sNtMapViewOfSection/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string75 = /\s\-Injector\sVirtualAllocEx/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string76 = /\s\-isbeacon\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string77 = /\sJspShell\sua/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string78 = /\sk8gege520\s/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string79 = /\skdbof\.cpp/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string80 = /\sLadon\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string81 = /\sLadon\.py/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string82 = /\s\-\-load\-shellcode\s/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string83 = /\smalleable\.profile/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string84 = /\smalleable\-c2\-randomizer/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string85 = /\smemreader\.c\s/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string86 = /\sMemReader_BoF/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string87 = /\sms17010\s\-i\s/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string88 = /\sms17010\s\-n\s/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string89 = /\sNTLMv1\scaptured\s/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string90 = /\s\-o\s\/share\/payloads\// nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string91 = /\soxidfind\s\-i\s/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string92 = /\soxidfind\s\-n\s/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string93 = /\s\-\-payload\-types\sall/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string94 = /\s\-\-payload\-types\sbin/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string95 = /\s\-\-payload\-types\sdll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string96 = /\s\-\-payload\-types\sexe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string97 = /\s\-\-payload\-types\sps1/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string98 = /\s\-\-payload\-types\spy/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string99 = /\s\-\-payload\-types\ssvc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string100 = /\s\-\-payload\-types\svbs/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string101 = /\s\-PE_Clone\s/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string102 = /\sPerform\sS4U\sconstrained\sdelegation\sabuse/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string103 = /\spipename_stager\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string104 = /\s\-pipename_stager\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string105 = /\spyasn1\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string106 = /\spyasn1\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string107 = /\srai\-attack\-dns/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string108 = /\srai\-attack\-http/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string109 = /\sReadFromLsass/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string110 = /\s\-RealCmdLine\s/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string111 = /\srustbof\s/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string112 = /\sScareCrow\.go/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string113 = /\sScareCrow\.go/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string114 = /\sSeriousSam\.Execute\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string115 = /\sSetMzLogonPwd\s/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string116 = /\ssigflip\.c\s/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string117 = /\sSigFlip\.exe/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string118 = /\sSigFlip\.PE/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string119 = /\ssigflip\.x64\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string120 = /\ssigflip\.x86\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string121 = /\sSigLoader\s/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string122 = /\sSigwhatever/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string123 = /\sspawn\.x64\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string124 = /\sspawn\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string125 = /\sspawnto_x64\s/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string126 = /\sspawnto_x86\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string127 = /\sSpoolFool\s.{0,1000}\.dll/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string128 = /\sStayKit\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string129 = /\sstriker\.py/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string130 = /\sSweetPotato\sby\s\@_EthicalChaos/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string131 = /\sSysWhispers/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string132 = /\sTikiLoader/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string133 = /\sTokenStrip\.c\s/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string134 = /\sTokenStripBOF\.o\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string135 = /\sTSCHRPCAttack/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string136 = /\s\-urlcache\s.{0,1000}\/debase64\// nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string137 = /\s\-wordlist\s.{0,1000}\s\-spawnto\s/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string138 = /\sWriteToLsass/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string139 = /\sxpipe/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string140 = /\$C2_SERVER/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string141 = /\%comspec\%\s\/k\s.{0,1000}\.bat/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string142 = /\.\/c2lint\s/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string143 = /\.\/Dent\s\-/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string144 = /\.\/manjusaka/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string145 = /\.\/ScareCrow\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string146 = /\.\/SourcePoint\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string147 = /\.admin\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string148 = /\.api\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string149 = /\.apps\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string150 = /\.beta\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string151 = /\.blog\.123456\./ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string152 = /\.cobaltstrike/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string153 = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string154 = /\.com\/dcsync\// nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string155 = /\.dev\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string156 = /\.events\.123456\./ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string157 = /\.exe\s.{0,1000}\s\-eventlog\s.{0,1000}Key\sManagement\sService/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string158 = /\.exe\s.{0,1000}\s\-\-source\sPersistence/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string159 = /\.feeds\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string160 = /\.files\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string161 = /\.forums\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string162 = /\.ftp\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string163 = /\.go\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string164 = /\.groups\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string165 = /\.help\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string166 = /\.imap\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string167 = /\.img\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string168 = /\.kb\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string169 = /\.lists\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string170 = /\.live\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string171 = /\.m\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string172 = /\.mail\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string173 = /\.media\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string174 = /\.mobile\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string175 = /\.mysql\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string176 = /\.news\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string177 = /\.photos\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string178 = /\.pic\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string179 = /\.pipename_stager/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string180 = /\.pop\.123456\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string181 = /\.py\s.{0,1000}\s\-\-teamserver\s/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string182 = /\.py\s127\.0\.0\.1\s50050\slogtracker\spassword/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string183 = /\.py.{0,1000}\s\-\-payload\s.{0,1000}\.ps1/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string184 = /\.py.{0,1000}\s\-service\-name\s.{0,1000}\s\-hashes\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string185 = /\.resources\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string186 = /\.search\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string187 = /\.secure\.123456\./ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string188 = /\.sharpgen\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string189 = /\.sites\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string190 = /\.smtp\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string191 = /\.ssl\.123456\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string192 = /\.stage\.123456\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string193 = /\.stage\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string194 = /\.static\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string195 = /\.status\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string196 = /\.store\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string197 = /\.support\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string198 = /\.videos\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string199 = /\.vpn\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string200 = /\.webmail\.123456\./ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string201 = /\.wiki\.123456\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string202 = /\/\.aggressor\.prop/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string203 = /\/\.ssh\/RAI\.pub/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string204 = /\/\/StaticSyscallsDump\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string205 = /\/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string206 = /\/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string207 = /\/AceLdr\.cna/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string208 = /\/adcs_enum\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string209 = /\/adcs_request\/adcs_request\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string210 = /\/adcs_request\/CertCli\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string211 = /\/adcs_request\/certenroll\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string212 = /\/adcs_request\/CertPol\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string213 = /\/AddUser\-Bof\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string214 = /\/AddUser\-Bof\// nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string215 = /\/AggressiveClean\.cna/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string216 = /\/aggressor\/.{0,1000}\.java/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string217 = /\/aggressor\-powerview/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string218 = /\/AggressorScripts/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string219 = /\/AggressorScripts/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string220 = /\/AggressorScripts/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string221 = /\/agscript\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string222 = /\/agscript\s/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string223 = /\/Alaris\.sln/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string224 = /\/ANGRYPUPPY\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string225 = /\/anthemtotheego\/CredBandit/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string226 = /\/artifactor\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string227 = /\/ase_docker\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string228 = /\/asprox\.profile/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string229 = /\/asprox\.profile/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string230 = /\/ASRenum\.cpp/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string231 = /\/ASRenum\.cs/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string232 = /\/ASRenum\-BOF/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string233 = /\/assets\/bin2uuids_file\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string234 = /\/AttackServers\// nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string235 = /\/auth\/cc2_auth\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string236 = /\/awesome\-pentest/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string237 = /\/backoff\.profile/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string238 = /\/backstab_src\// nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string239 = /\/BackupPrivSam\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string240 = /\/bazarloader\.profile/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string241 = /\/beacon\.h/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string242 = /\/beacon_compatibility/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string243 = /\/beacon_compatibility\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string244 = /\/beacon_funcs\// nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string245 = /\/beacon_health_check\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string246 = /\/beacon_http\// nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string247 = /\/beacon_notify\.cna/ nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string248 = /\/beaconhealth\.cna/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string249 = /\/beacon\-injection\// nocase ascii wide
        // Description: Cobaltstrike beacon object files
        // Reference: https://github.com/realoriginal/beacon-object-file
        $string250 = /\/beacon\-object\-file/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string251 = /\/BeaconTool\.java/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string252 = /\/bin\/AceLdr/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string253 = /\/bin\/Sleeper\.o/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string254 = /\/bluscreenofjeff\// nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string255 = /\/bof\.h/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string256 = /\/BOF\.NET\// nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string257 = /\/bof\.nim/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string258 = /\/bof\.x64\.o/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string259 = /\/bof\.x64\.o/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string260 = /\/bof\.x86\.o/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string261 = /\/bof\.x86\.o/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string262 = /\/bof\/bof\.c/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string263 = /\/bof\/bof\.vcxproj/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string264 = /\/bof\/IABOF/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string265 = /\/bof\/IAStart\.asm/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string266 = /\/BOF\-Builder/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string267 = /\/bof\-collection\// nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string268 = /\/BOFNETExamples\// nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string269 = /\/BOF\-RegSave/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string270 = /\/BofRunner\.cs/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string271 = /\/BOFs\.git/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string272 = /\/bof\-vs\-template\// nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string273 = /\/bof\-vs\-template\// nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string274 = /\/boku7\/spawn/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string275 = /\/boku7\/whereami\// nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string276 = /\/BokuLoader\.c/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string277 = /\/BokuLoader\.h/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string278 = /\/BokuLoader\// nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string279 = /\/BooExecutor\.cs/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string280 = /\/bq1iFEP2\/assert\/dll\// nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string281 = /\/bq1iFEP2\/assert\/exe\// nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string282 = /\/breg\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string283 = /\/breg\.x86\.o/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string284 = /\/build\/encrypted_shellcode/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string285 = /\/build\/formatted_shellcode/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string286 = /\/build\/shellcode/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string287 = /\/BuildBOFs\// nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string288 = /\/burpee\.py/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string289 = /\/BUYTHEAPTDETECTORNOW/ nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string290 = /\/BypassAV\// nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string291 = /\/bypassAV\-1\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string292 = /\/C2concealer/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string293 = /\/c2profile\./ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string294 = /\/c2profile\.go/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string295 = /\/C2script\// nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string296 = /\/cc2_frp\./ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string297 = /\/client\/bof\/.{0,1000}\.asm/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string298 = /\/clipboardinject\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string299 = /\/clipboardinject\// nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string300 = /\/clipmon\/clipmon\.sln/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string301 = /\/clipmon\/dll\// nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string302 = /\/cna\/pipetest\.cna/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string303 = /\/cobaltclip\.c/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string304 = /\/cobaltclip\.o/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string305 = /\/Cobalt\-Clip\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string306 = /\/cobaltstrike/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string307 = /\/cobalt\-strike/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string308 = /\/CoffeeLdr\.c/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string309 = /\/CoffeeLdr\// nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string310 = /\/COFFLoader/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string311 = /\/COFFLoader2\// nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string312 = /\/com\/blackh4t\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string313 = /\/comfoo\.profile/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string314 = /\/CookieProcessor\.cs/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string315 = /\/core\/browser_darwin\.go/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string316 = /\/core\/browser_linux\.go/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string317 = /\/core\/browser_windows\.go/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string318 = /\/Cracked5pider\// nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string319 = /\/credBandit\// nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string320 = /\/CredEnum\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string321 = /\/CredEnum\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string322 = /\/CredEnum\.h/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string323 = /\/CredPrompt\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string324 = /\/CredPrompt\/credprompt\.c/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string325 = /\/CrossC2\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string326 = /\/CrossC2\// nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string327 = /\/CrossC2Kit/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string328 = /\/CrossC2Kit\// nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string329 = /\/CrossNet\-Beta\// nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string330 = /\/crypt0p3g\// nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string331 = /\/cs2modrewrite\// nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string332 = /\/CS\-BOFs\// nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string333 = /\/CSharpWinRM/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string334 = /\/C\-\-Shellcode/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string335 = /\/CS\-Loader\.go/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string336 = /\/CS\-Loader\// nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string337 = /\/csOnvps\// nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string338 = /\/csOnvps\// nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string339 = /\/cs\-rdll\-ipc\-example\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string340 = /\/CS\-Remote\-OPs\-BOF/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string341 = /\/cs\-token\-vault\// nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string342 = /\/curl\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string343 = /\/curl\.x64\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string344 = /\/curl\.x86\.o/ nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string345 = /\/custom_payload_generator\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string346 = /\/CWoNaJLBo\/VTNeWw11212\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string347 = /\/CWoNaJLBo\/VTNeWw11213\// nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string348 = /\/DCOM\sLateral\sMovement\// nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string349 = /\/defender\-exclusions\/.{0,1000}defender/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string350 = /\/defender\-exclusions\/.{0,1000}exclusion/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string351 = /\/DelegationBOF\// nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string352 = /\/demo_bof\.c/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string353 = /\/Dent\/.{0,1000}\/Loader\/Loader\.go/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string354 = /\/Dent\/Dent\.go/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string355 = /\/Dent\/Loader/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string356 = /\/DesertFox\/archive\/.{0,1000}\.zip/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string357 = /\/detect\-hooks\.c/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string358 = /\/detect\-hooks\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string359 = /\/detect\-hooks\.h/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string360 = /\/Detect\-Hooks\// nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string361 = /\/dist\/fw_walk\./ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string362 = /\/DLL\-Hijack/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string363 = /\/Doge\-Loader\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string364 = /\/DotNet\/SigFlip/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string365 = /\/dukes_apt29\.profile/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string366 = /\/dump_lsass\./ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string367 = /\/dumpert\.c/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string368 = /\/Dumpert\// nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string369 = /\/dumpXor\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string370 = /\/dumpXor\/dumpXor/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string371 = /\/ElevateKit\/elevate\./ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string372 = /\/ELFLoader\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string373 = /\/emotet\.profile/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string374 = /\/enableuser\/enableuser\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string375 = /\/enableuser\/enableuser\.x86\./ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string376 = /\/EnumCLR\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string377 = /\/enumerate\.cna/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string378 = /\/Erebus\/.{0,1000}\.dll/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string379 = /\/Erebus\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string380 = /\/Erebus\-email\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string381 = /\/etumbot\.profile/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string382 = /\/etw\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string383 = /\/etw\.x64\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string384 = /\/etw\.x86\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string385 = /\/EventViewerUAC\// nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string386 = /\/EventViewerUAC\// nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string387 = /\/evil\.cpp/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string388 = /\/exports_function_hid\.txt/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string389 = /\/fiesta\.profile/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string390 = /\/fiesta2\.profile/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string391 = /\/final_shellcode_size\.txt/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string392 = /\/FindModule\.c/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string393 = /\/FindObjects\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string394 = /\/Fodetect\-hooksx64/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string395 = /\/FuckThatPacker/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string396 = /\/G0ldenGunSec\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string397 = /\/gandcrab\.profile/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string398 = /\/geacon\/.{0,1000}beacon/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string399 = /\/geacon_pro/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string400 = /\/get\-loggedon\/.{0,1000}\.c/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string401 = /\/get\-system\/getsystem\.c/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string402 = /\/GetWebDAVStatus_BOF\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string403 = /\/globeimposter\.profile/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string404 = /\/guervild\/BOFs/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string405 = /\/hancitor\.profile/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com/EspressoCake/HandleKatz_BOF
        $string406 = /\/HandleKatz_BOF/ nocase ascii wide
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
        $string413 = /\/HouQing\/.{0,1000}\/Loader\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string414 = /\/injectAmsiBypass\// nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string415 = /\/inject\-assembly\// nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string416 = /\/injectEtw\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string417 = /\/Injection\/clipboard\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string418 = /\/Injection\/conhost\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string419 = /\/Injection\/createremotethread\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string420 = /\/Injection\/ctray\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string421 = /\/Injection\/dde\// nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string422 = /\/Injection\/Injection\.cna/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string423 = /\/Injection\/kernelcallbacktable/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string424 = /\/Injection\/ntcreatethread/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string425 = /\/Injection\/ntcreatethread\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string426 = /\/Injection\/ntqueueapcthread/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string427 = /\/Injection\/setthreadcontext/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string428 = /\/Injection\/svcctrl\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string429 = /\/Injection\/tooltip\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string430 = /\/Injection\/uxsubclassinfo/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string431 = /\/InlineWhispers/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string432 = /\/Internals\/Coff\.cs/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string433 = /\/Inveigh\.txt/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string434 = /\/Invoke\-Bof\// nocase ascii wide
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
        $string438 = /\/K8_CS_.{0,1000}_.{0,1000}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string439 = /\/k8gege\// nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string440 = /\/k8gege\/scrun\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string441 = /\/k8gege520/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string442 = /\/kdstab\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string443 = /\/KDStab\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string444 = /\/KDStab\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string445 = /\/Kerbeus\-BOF\.git/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string446 = /\/Kerbeus\-BOF\// nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string447 = /\/KernelMii\.c/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string448 = /\/Koh\/.{0,1000}\.cs/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string449 = /\/kronos\.profile/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string450 = /\/Ladon\.go/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string451 = /\/Ladon\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string452 = /\/Ladon\.py/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string453 = /\/Ladon\/Ladon\./ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string454 = /\/Ladon\/obj\/x86/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string455 = /\/LadonGo\// nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string456 = /\/LetMeOutSharp\// nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string457 = /\/lib\/ipLookupHelper\.py/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string458 = /\/loader\/x64\/Release\/loader\.exe/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string459 = /\/loadercrypt_.{0,1000}\.php/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string460 = /\/logs\/.{0,1000}\/becon_.{0,1000}\.log/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string461 = /\/logs\/beacon_log/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string462 = /\/lpBunny\/bof\-registry/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string463 = /\/lsass\/beacon\.h/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string464 = /\/magnitude\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string465 = /\/malleable\-c2/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string466 = /\/manjusaka\/plugins/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string467 = /\/MemReader_BoF\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string468 = /\/mimipenguin\.c/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string469 = /\/mimipenguin\// nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string470 = /\/minimal_elf\.h/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string471 = /\/Misc\/donut\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string472 = /\/Mockingjay_BOF\.git/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string473 = /\/Modules\/Exitservice\/uinit\.exe/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string474 = /\/Mr\-Un1k0d3r\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string475 = /\/Native\/SigFlip\// nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string476 = /\/nccgroup\/nccfsas\// nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string477 = /\/Needle_Sift_BOF\// nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string478 = /\/nettitude\/RunOF\// nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string479 = /\/NetUser\.cpp/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string480 = /\/NetUser\.exe/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string481 = /\/netuserenum\// nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string482 = /\/Network\/PortScan\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string483 = /\/Newtonsoft\.Json\.dll/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string484 = /\/No\-Consolation\.git/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string485 = /\/ntlmrelayx\// nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string486 = /\/oab\-parse\/mspack\..{0,1000}\.dll/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string487 = /\/OG\-Sadpanda\// nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string488 = /\/On_Demand_C2\// nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string489 = /\/opt\/implant\// nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string490 = /\/opt\/rai\// nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string491 = /\/optiv\/Dent\// nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string492 = /\/oscp\.profile/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string493 = /\/outflanknl\// nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string494 = /\/output\/payloads\// nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string495 = /\/p292\/Phant0m/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string496 = /\/package\/portscan\/.{0,1000}\.go/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string497 = /\/password\/mimipenguin\// nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string498 = /\/payload_scripts/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string499 = /\/payload_scripts\/artifact/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string500 = /\/PersistBOF\// nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string501 = /\/PhishingServer\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string502 = /\/pitty_tiger\.profile/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string503 = /\/popCalc\.bin/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string504 = /\/PortBender\// nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string505 = /\/portscan\.cna/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string506 = /\/POSeidon\.profile/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string507 = /\/PowerView\.cna/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string508 = /\/PowerView3\.cna/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string509 = /\/PPEnum\// nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string510 = /\/ppldump\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string511 = /\/PPLDump_BOF\// nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string512 = /\/PrintMonitorDll\./ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string513 = /\/PrintMonitorDll\// nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string514 = /\/PrintSpoofer\// nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string515 = /\/PrivilegeEscalation\// nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string516 = /\/proberbyte\.go/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string517 = /\/Proxy_Def_File_Generator\.cna/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string518 = /\/putter\.profile/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string519 = /\/pyasn1\// nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string520 = /\/pycobalt\-/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string521 = /\/pycobalt\// nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string522 = /\/pystinger\.zip/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string523 = /\/qakbot\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string524 = /\/quantloader\.profile/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string525 = /\/RAI\.git/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string526 = /\/ramnit\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string527 = /\/ratankba\.profile/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string528 = /\/raw_shellcode_size\.txt/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string529 = /\/RC4Payload32\.txt/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string530 = /\/RCStep\/CSSG\// nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string531 = /\/readfile_bof\./ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string532 = /\/Readfile_BoF\// nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string533 = /\/red\-team\-scripts/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string534 = /\/RedWarden\.git/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string535 = /\/RegistryPersistence\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string536 = /\/Registry\-Recon\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string537 = /\/Remote\/adcs_request\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string538 = /\/Remote\/office_tokens\// nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string539 = /\/Remote\/procdump\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string540 = /\/Remote\/ProcessDestroy\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string541 = /\/Remote\/ProcessListHandles\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string542 = /\/Remote\/schtaskscreate\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string543 = /\/Remote\/schtasksrun\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string544 = /\/Remote\/setuserpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string545 = /\/Remote\/setuserpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string546 = /\/Remote\/unexpireuser\// nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string547 = /\/remotereg\.c/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string548 = /\/remotereg\.o/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string549 = /\/RunOF\/RunOF\// nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string550 = /\/runshellcode\./ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string551 = /\/S3cur3Th1sSh1t\// nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string552 = /\/saefko\.profile/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string553 = /\/ScareCrow\s\-I\s/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string554 = /\/ScRunHex\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string555 = /\/searchsploit/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string556 = /\/Seatbelt\.txt/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string557 = /\/secinject\.c/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string558 = /\/self_delete\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string559 = /\/SeriousSam\.sln/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string560 = /\/serverscan\/CobaltStrike/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string561 = /\/serverscan_Air/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string562 = /\/serverscan_pro/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string563 = /\/ServerScanForLinux\// nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string564 = /\/ServerScanForWindows\// nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string565 = /\/ServerScanForWindows\/PE/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string566 = /\/ServiceMove\-BOF\// nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string567 = /\/Services\/TransitEXE\.exe/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string568 = /\/setuserpass\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string569 = /\/setuserpass\.x86\./ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string570 = /\/SharpCalendar\/.{0,1000}\./ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string571 = /\/SharpCat\// nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string572 = /\/SharpCompile\// nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string573 = /\/sharpcompile_.{0,1000}\./ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string574 = /\/SharpCradle\// nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string575 = /\/SharpSword\/SharpSword/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string576 = /\/ShellCode_Loader/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string577 = /\/shspawnas\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string578 = /\/sigflip\.x64\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string579 = /\/sigflip\.x86\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string580 = /\/SigLoader\.go/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string581 = /\/SigLoader\// nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string582 = /\/SilentClean\.exe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string583 = /\/SilentClean\/SilentClean\/.{0,1000}\.cs/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string584 = /\/silentdump\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string585 = /\/silentdump\.h/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string586 = /\/sleep_python_bridge\// nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string587 = /\/Sleeper\/Sleeper\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string588 = /\/sleepmask\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string589 = /\/spawn\.git/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string590 = /\/spoolsystem\/SpoolTrigger\// nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string591 = /\/Spray\-AD\./ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string592 = /\/Spray\-AD\// nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string593 = /\/src\/Sleeper\.cpp/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string594 = /\/StaticSyscallsAPCSpawn\// nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string595 = /\/StaticSyscallsInject\// nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string596 = /\/StayKit\.cna/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string597 = /\/Staykit\/StayKit\./ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string598 = /\/striker\.py/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string599 = /\/string_of_paerls\.profile/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string600 = /\/suspendresume\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string601 = /\/suspendresume\.x86/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string602 = /\/SweetPotato_CS/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string603 = /\/SyscallsInject\// nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string604 = /\/taidoor\.profile/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string605 = /\/tcpshell\.py/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string606 = /\/test32\.dll/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string607 = /\/test64\.dll/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string608 = /\/tests\/test\-bof\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string609 = /\/tevora\-threat\/PowerView/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string610 = /\/tgtParse\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string611 = /\/tgtParse\/tgtParse\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string612 = /\/ticketConverter\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string613 = /\/TikiLoader\// nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string614 = /\/TikiSpawn\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string615 = /\/TikiSpawn\// nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string616 = /\/TokenStripBOF/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string617 = /\/tools\/BeaconTool\// nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string618 = /\/Tools\/spoolsystem\// nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string619 = /\/Tools\/Squeak\/Squeak/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string620 = /\/trick_ryuk\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string621 = /\/trickbot\.profile/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string622 = /\/UAC\-SilentClean\// nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string623 = /\/unhook\-bof/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/Cobalt-Strike/unhook-bof
        $string624 = /\/unhook\-bof/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string625 = /\/UTWOqVQ132\// nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string626 = /\/vssenum\// nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string627 = /\/WdToggle\.c/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string628 = /\/WdToggle\.h/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string629 = /\/webshell\/.{0,1000}\.aspx/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string630 = /\/webshell\/.{0,1000}\.jsp/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string631 = /\/webshell\/.{0,1000}\.php/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string632 = /\/wifidump\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string633 = /\/WindowsVault\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string634 = /\/WindowsVault\.h/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string635 = /\/winrm\.cpp/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string636 = /\/winrmdll/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string637 = /\/winrm\-reflective\-dll\// nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string638 = /\/Winsocky\.git/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string639 = /\/WMI\sLateral\sMovement\// nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string640 = /\/wwlib\/lolbins\// nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string641 = /\/xen\-mimi\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string642 = /\/xor\/stager\.txt/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string643 = /\/xor\/xor\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string644 = /\/xPipe\// nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string645 = /\/yanghaoi\/_CNA/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string646 = /\/zerologon\.cna/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string647 = /\[\'spawnto\'\]/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string648 = /\\\\GetWebDAVStatus\.exe/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string649 = /\\\\pipe\\\\DAV\sRPC\sSERVICE/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string650 = /\\8e8988b257e9dd2ea44ff03d44d26467b7c9ec16/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string651 = /\\asreproasting\.c/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string652 = /\\beacon\.exe/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string653 = /\\CrossC2\./ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string654 = /\\CROSSNET\\CROSSNET\\/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string655 = /\\dumpert\./ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string656 = /\\Dumpert\\/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string657 = /\\DumpShellcode/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string658 = /\\dumpXor\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string659 = /\\dumpXor\\x64\\/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string660 = /\\ELF\\portscan/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string661 = /\\ELF\\serverscan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string662 = /\\evil\.dll/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string663 = /\\GetWebDAVStatus\\/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string664 = /\\GetWebDAVStatus_x64/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string665 = /\\HackBrowserData/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string666 = /\\HiddenDesktop\\/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string667 = /\\HostEnum\.ps1/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string668 = /\\kdstab\.exe/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string669 = /\\kerberoasting\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string670 = /\\Kerbeus\-BOF\\/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string671 = /\\Koh\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string672 = /\\Koh\.pdb/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string673 = /\\Koh\\Koh\./ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string674 = /\\Ladon\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string675 = /\\Ladon\.ps1/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string676 = /\\LogonScreen\.exe/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string677 = /\\lsass\.dmp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string678 = /\\Mockingjay_BOF\./ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string679 = /\\No\-Consolation\\source\\/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string680 = /\\portbender\./ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string681 = /\\PowerView\.cna/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string682 = /\\PowerView\.exe/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string683 = /\\PowerView\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string684 = /\\PowerView3\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string685 = /\\RunBOF\.exe/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string686 = /\\RunOF\.exe/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string687 = /\\RunOF\\bin\\/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string688 = /\\samantha\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string689 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string690 = /\\SigFlip\.exe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string691 = /\\SilentClean\.exe/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string692 = /\\StayKit\.cna/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string693 = /\\systemic\.txt/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string694 = /\\TASKSHELL\.EXE/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string695 = /\\TikiCompiler\.txt/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string696 = /\\TikiService\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string697 = /\\TikiSpawn\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string698 = /\\tikispawn\.xml/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string699 = /\\TikiTorch\\Aggressor/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string700 = /_cobaltstrike/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string701 = /_find_sharpgen_dll/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string702 = /_pycobalt_/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string703 = /_tcp_cc2\(/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string704 = /_udp_cc2\(/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string705 = /\<CoffeLdr\.h\>/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string706 = /0xthirteen\/MoveKit/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string707 = /0xthirteen\/StayKit/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string708 = /0xthirteen\/StayKit/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string709 = /4d5350c8\-7f8c\-47cf\-8cde\-c752018af17e/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string710 = /516280565958/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string711 = /516280565959/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string712 = /5a40f11a99d0db4a0b06ab5b95c7da4b1c05b55a99c7c443021bff02c2cf93145c53ff5b/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string713 = /5e98194a01c6b48fa582a6a9fcbb92d6/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string714 = /5e98194a01c6b48fa582a6a9fcbb92d6/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string715 = /6e7645c4\-32c5\-4fe3\-aabf\-e94c2f4370e7/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string716 = /713724C3\-2367\-49FA\-B03F\-AB4B336FB405/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string717 = /732211ae\-4891\-40d3\-b2b6\-85ebd6f5ffff/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string718 = /7CFC52\.dll/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string719 = /7CFC52CD3F\.dll/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string720 = /913d774e5cf0bfad4adfa900997f7a1a/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string721 = /913d774e5cf0bfad4adfa900997f7a1a/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string722 = /AceLdr\..{0,1000}\.bin/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string723 = /AceLdr\.zip/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string724 = /adcs_enum\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string725 = /adcs_enum_com\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string726 = /adcs_enum_com2\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string727 = /AddUser\-Bof\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string728 = /AddUser\-Bof\.git/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string729 = /AddUser\-Bof\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string730 = /AddUser\-Bof\.x64/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string731 = /AddUser\-Bof\.x86/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string732 = /AddUserToDomainGroup\s.{0,1000}Domain\sAdmins/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string733 = /AddUserToDomainGroup\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string734 = /AddUserToDomainGroup\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string735 = /Adminisme\/ServerScan\// nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string736 = /ag_load_script/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string737 = /AggressiveProxy\.cna/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string738 = /aggressor\.beacons/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string739 = /aggressor\.bshell/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string740 = /aggressor\.cna/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string741 = /aggressor\.dialog/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string742 = /aggressor\.println/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string743 = /aggressor\.py/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string744 = /Aggressor\/TikiTorch/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string745 = /Aggressor\-Scripts/ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string746 = /aggressor\-scripts/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string747 = /ajpc500\/BOFs/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string748 = /Alphabug_CS/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string749 = /Alphabug_CS/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string750 = /AlphabugX\/csOnvps/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string751 = /AlphabugX\/csOnvps/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string752 = /Already\sSYSTEM.{0,1000}not\selevating/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string753 = /ANGRYPUPPY2\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string754 = /anthemtotheego\/Detect\-Hooks/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string755 = /apokryptein\/secinject/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string756 = /applocker_enum/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string757 = /applocker\-enumerator/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string758 = /apt1_virtuallythere\.profile/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string759 = /arsenal_kit\.cna/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string760 = /artifact\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string761 = /artifact\.cna/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string762 = /artifact\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string763 = /artifact\.x64\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string764 = /artifact\.x86\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string765 = /artifact\.x86\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string766 = /artifact_payload/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string767 = /artifact_payload/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string768 = /artifact_stageless/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string769 = /artifact_stageless/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string770 = /artifact_stager/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string771 = /artifact_stager/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string772 = /artifact32.{0,1000}\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string773 = /artifact32\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string774 = /artifact32\.dll/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string775 = /artifact32\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string776 = /artifact32\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string777 = /artifact32big\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string778 = /artifact32big\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string779 = /artifact32svc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string780 = /artifact32svcbig\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string781 = /artifact64.{0,1000}\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string782 = /artifact64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string783 = /artifact64\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string784 = /artifact64\.x64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string785 = /artifact64big\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string786 = /artifact64big\.x64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string787 = /artifact64svc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string788 = /artifact64svcbig\.exe/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string789 = /artifactbig64\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string790 = /artifactuac.{0,1000}\.dll/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string791 = /asktgs\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string792 = /ASRenum\-BOF\./ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string793 = /asreproasting\.x64/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string794 = /Assemblies\/SharpMove\.exe/ nocase ascii wide
        // Description: Cobalt Strike BOFs
        // Reference: https://github.com/AttackTeamFamily/cobaltstrike-bof-toolset
        $string795 = /AttackTeamFamily.{0,1000}\-bof\-toolset/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string796 = /ausecwa\/bof\-registry/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string797 = /auth\/cc2_ssh\./ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string798 = /Backdoor\sLNK/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string799 = /\-\-backdoor\-all/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string800 = /backdoorlnkdialog/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string801 = /backstab\.x64\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string802 = /backstab\.x86\./ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string803 = /BackupPrivSAM\s\\\\/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string804 = /backupprivsam\./ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string805 = /BadPotato\.exe/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string806 = /bawait_upload/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string807 = /bawait_upload_raw/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string808 = /bblockdlls/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string809 = /bbrowserpivot/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string810 = /bbrowserpivot/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string811 = /bbypassuac/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string812 = /bcc2_setenv/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string813 = /bcc2_spawn/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string814 = /bcrossc2_load_dyn/ nocase ascii wide
        // Description: Malleable C2 Profiles. A collection of profiles used in different projects using Cobalt Strike & Empire.
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string815 = /BC\-SECURITY.{0,1000}Malleable/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string816 = /bdcsync/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string817 = /bdllinject/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string818 = /bdllinject/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string819 = /bdllload/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string820 = /bdllload/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string821 = /bdllspawn/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string822 = /bdllspawn/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string823 = /Beacon\sPayload\sGenerator/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string824 = /beacon\..{0,1000}winsrv\.dll/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string825 = /beacon\.CommandBuilder/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string826 = /beacon\.CommandBuilder/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string827 = /beacon\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string828 = /beacon\.exe/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string829 = /beacon\.exe/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string830 = /beacon\.nim/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string831 = /Beacon\.Object\.File\.zip/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string832 = /beacon\.x64.{0,1000}\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string833 = /beacon\.x64.{0,1000}\.exe/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string834 = /beacon\.x64\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string835 = /beacon\.x86.{0,1000}\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string836 = /beacon\.x86.{0,1000}\.exe/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string837 = /beacon_api\.h/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string838 = /beacon_bottom\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string839 = /Beacon_Com_Struct/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string840 = /beacon_command_describe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string841 = /beacon_command_detail/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string842 = /beacon_command_detail/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string843 = /beacon_command_register/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string844 = /beacon_command_register/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string845 = /beacon_commands/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string846 = /beacon_compatibility\.c/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string847 = /beacon_compatibility\.h/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string848 = /beacon_elevator_describe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string849 = /beacon_elevator_describe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string850 = /beacon_elevator_register/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string851 = /beacon_elevator_register/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string852 = /beacon_elevator_register/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string853 = /beacon_elevators/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string854 = /beacon_elevators/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string855 = /beacon_execute_job/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string856 = /beacon_exploit_describe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string857 = /beacon_exploit_register/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string858 = /beacon_funcs\.c/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string859 = /beacon_funcs\.h/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string860 = /beacon_funcs\.x64\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string861 = /beacon_funcs\.x86\./ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string862 = /beacon_generate\.py/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string863 = /Beacon_GETPOST/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string864 = /beacon_host_script/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string865 = /beacon_host_script/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string866 = /beacon_inline_execute/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string867 = /beacon_inline_execute/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string868 = /beacon_inline_execute/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string869 = /beacon_inline_execute/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string870 = /beacon_log_clean/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string871 = /beacon_output_ps\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string872 = /beacon_print/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string873 = /BEACON_RDLL_/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string874 = /beacon_remote_exec_/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string875 = /beacon_remote_exec_method_describe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string876 = /beacon_remote_exec_method_register/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string877 = /beacon_remote_exec_methods/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string878 = /beacon_remote_exploit/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string879 = /beacon_remote_exploit_arch/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string880 = /beacon_remote_exploit_describe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string881 = /beacon_remote_exploit_register/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string882 = /beacon_remote_exploits/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string883 = /beacon_smb\.exe/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string884 = /Beacon_Stage_p2_Stuct/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string885 = /beacon_stage_pipe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string886 = /beacon_stage_pipe/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string887 = /Beacon_Stage_Struct_p1/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string888 = /Beacon_Stage_Struct_p3/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string889 = /beacon_stage_tcp/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string890 = /beacon_stage_tcp/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string891 = /beacon_test\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string892 = /beacon_top\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string893 = /beacon_top_callback/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string894 = /BeaconApi\.cs/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string895 = /beacon\-c2\-go/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string896 = /BeaconCleanupProcess/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string897 = /BeaconConsoleWriter\.cs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string898 = /BeaconGetSpawnTo/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string899 = /BeaconGetSpawnTo/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string900 = /BeaconGetSpawnTo/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string901 = /beacongrapher\.py/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string902 = /BeaconInjectProcess/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string903 = /BeaconInjectProcess/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string904 = /BeaconInjectTemporaryProcess/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string905 = /BeaconInjectTemporaryProcess/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string906 = /BeaconJob\.cs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string907 = /BeaconJobWriter\.cs/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string908 = /beaconlogs\.json/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string909 = /beaconlogtracker\.py/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string910 = /BeaconNote\.cna/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string911 = /BeaconNotify\.cna/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string912 = /BeaconObject\.cs/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string913 = /BeaconOutputStreamW/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string914 = /BeaconOutputWriter\.cs/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string915 = /BeaconPrintf\(/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string916 = /BeaconPrintf/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string917 = /BeaconPrintToStreamW/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string918 = /BeaconSpawnTemporaryProcess/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string919 = /BeaconSpawnTemporaryProcess/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string920 = /BeaconTool\s\-/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string921 = /BeaconTool\/lib\/sleep\.jar/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string922 = /BeaconUseToken/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string923 = /bgetprivs/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string924 = /bhashdump/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string925 = /bin\/bof_c\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string926 = /bin\/bof_nim\.o/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string927 = /bkerberos_ccache_use/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string928 = /bkerberos_ticket_purge/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string929 = /bkerberos_ticket_use/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string930 = /bkeylogger/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string931 = /blockdlls\sstart/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string932 = /blockdlls\sstop/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string933 = /bloginuser/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string934 = /blogonpasswords/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string935 = /BOF\sprototype\sworks\!/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string936 = /bof.{0,1000}\/CredEnum\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string937 = /BOF\/.{0,1000}procdump\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string938 = /bof_allocator/ nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string939 = /bof_helper\.py/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string940 = /bof_net_user\.c/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string941 = /bof_net_user\.o/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string942 = /bof_reuse_memory/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string943 = /BOF2shellcode/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string944 = /bof2shellcode\.py/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string945 = /BOF\-DLL\-Inject/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string946 = /bofentry::bof_entry/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string947 = /BOF\-ForeignLsass/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string948 = /BOF\-IShellWindows\-DCOM\./ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string949 = /BofLdapSignCheck/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string950 = /bofloader\.bin/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string951 = /bofnet.{0,1000}SeriousSam\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string952 = /BOFNET\.Bofs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string953 = /bofnet\.cna/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string954 = /BOFNET\.csproj/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string955 = /BOFNET\.sln/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string956 = /bofnet_boo\s.{0,1000}\.boo/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string957 = /bofnet_execute\s/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string958 = /bofnet_execute\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string959 = /bofnet_init/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string960 = /bofnet_job\s/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string961 = /bofnet_jobkill/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string962 = /bofnet_jobs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string963 = /bofnet_jobstatus\s/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string964 = /bofnet_list/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string965 = /bofnet_listassembiles/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string966 = /bofnet_load\s.{0,1000}\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string967 = /bofnet_shutdown/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string968 = /BOFNET_Tests/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string969 = /bofportscan\s/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string970 = /bof\-quser\s.{0,1000}\./ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string971 = /bof\-quser\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string972 = /bof\-rdphijack/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string973 = /bof\-regsave\s/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string974 = /BofRunnerOutput/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string975 = /BOFs.{0,1000}\/SyscallsSpawn\// nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string976 = /Bofs\/AssemblyLoader/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string977 = /bof\-servicemove\s/ nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string978 = /bof\-trustedpath\-uacbypass/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string979 = /boku_pe_customMZ/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string980 = /boku_pe_customPE/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string981 = /boku_pe_dll/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string982 = /boku_pe_mask_/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string983 = /boku_pe_MZ_from_C2Profile/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string984 = /boku_strrep/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string985 = /boku7\/BokuLoader/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string986 = /boku7\/HOLLOW/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string987 = /BokuLoader\.cna/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string988 = /BokuLoader\.exe/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string989 = /BokuLoader\.x64/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string990 = /BooExecutorImpl\.cs/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string991 = /bpassthehash/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string992 = /bpowerpick/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string993 = /bpsexec_command/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string994 = /bpsexec_command/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string995 = /bpsexec_psh/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string996 = /bpsinject/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string997 = /bpsinject/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string998 = /breg\sadd\s.{0,1000}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string999 = /breg\sdelete\s.{0,1000}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1000 = /breg\squery\s.{0,1000}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1001 = /breg_add_string_value/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1002 = /bremote_exec/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1003 = /browser_\#\#/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1004 = /browserpivot\s/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1005 = /brun_script_in_mem/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1006 = /brunasadmin/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1007 = /bshinject/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1008 = /bshinject/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1009 = /bshspawn/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1010 = /bsteal_token/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1011 = /bsteal_token/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1012 = /build\sSourcePoint\.go/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1013 = /build\/breg\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1014 = /build_c_shellcode/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1015 = /BuildBOFs\.exe/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1016 = /BuildBOFs\.sln/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1017 = /bupload_raw.{0,1000}\.dll/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1018 = /burp2malleable\./ nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string1019 = /BypassAV\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1020 = /bypass\-pipe\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string1021 = /byt3bl33d3r\/BOF\-Nim/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1022 = /\-c\sBOF\.cpp\s\-o\sBOF\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1023 = /\-c\sBOF\.cpp\s\-o\sBOF\.x64\.o/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1024 = /C:\\Temp\\poc\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1025 = /C:\\Windows\\Temp\\move\.exe/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1026 = /C:\\Windows\\Temp\\moveme\.exe/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1027 = /C\?\?\/generator\.cpp/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1028 = /c2lint\s/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1029 = /C2ListenerPort/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1030 = /\-c2\-randomizer\.py/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1031 = /C2ReverseClint/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1032 = /C2ReverseProxy/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1033 = /C2ReverseServer/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1034 = /C2script\/proxy\./ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1035 = /\'c2server\'/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1036 = /CACTUSTORCH\.cna/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1037 = /CACTUSTORCH\.cs/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1038 = /CACTUSTORCH\.hta/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1039 = /CACTUSTORCH\.js/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1040 = /CACTUSTORCH\.vba/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1041 = /CACTUSTORCH\.vbe/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1042 = /CACTUSTORCH\.vbs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1043 = /CALLBACK_HASHDUMP/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1044 = /CALLBACK_KEYSTROKES/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1045 = /CALLBACK_NETVIEW/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1046 = /CALLBACK_PORTSCAN/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1047 = /CALLBACK_TOKEN_STOLEN/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1048 = /CallBackDump.{0,1000}dumpXor/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1049 = /CallbackDump\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1050 = /careCrow.{0,1000}_linux_amd64/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1051 = /cat\s.{0,1000}\.bin\s\|\sbase64\s\-w\s0\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1052 = /cc2_keystrokes_/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1053 = /cc2_mimipenguin\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1054 = /cc2_portscan_/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1055 = /cc2_rebind_.{0,1000}_get_recv/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1056 = /cc2_rebind_.{0,1000}_get_send/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1057 = /cc2_rebind_.{0,1000}_post_recv/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1058 = /cc2_rebind_.{0,1000}_post_send/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1059 = /cc2_udp_server/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1060 = /cc2FilesColor\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1061 = /cc2ProcessColor\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1062 = /CCob\/BOF\.NET/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1063 = /cd\s\.\/whereami\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1064 = /ChatLadon\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1065 = /ChatLadon\.rar/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1066 = /check_and_write_IAT_Hook/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1067 = /check_function\sntdll\.dll\sEtwEventWrite/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1068 = /checkIfHiddenAPICall/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1069 = /chromeKey\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1070 = /chromeKey\.x86/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1071 = /chromiumkeydump/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1072 = /cHux014r17SG3v4gPUrZ0BZjDabMTY2eWDj1tuYdREBg/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1073 = /clipboardinject\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1074 = /clipboardinject\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1075 = /clipboardinject\.x86/ nocase ascii wide
        // Description: CLIPBRDWNDCLASS process injection technique(BOF) - execute beacon shellcode in callback
        // Reference: https://github.com/BronzeTicket/ClipboardWindow-Inject
        $string1076 = /ClipboardWindow\-Inject/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1077 = /clipmon\.sln/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1078 = /Cobalt\sStrike/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1079 = /cobaltclip\.cna/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1080 = /cobaltclip\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1081 = /cobaltstrike\s/ nocase ascii wide
        // Description: cobaltstrike binary for windows - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network. While penetration tests focus on unpatched vulnerabilities and misconfigurations. these assessments benefit security operations and incident response.
        // Reference: https://www.cobaltstrike.com/
        $string1082 = /cobaltstrike/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1083 = /cobaltstrike\-/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1084 = /cobalt\-strike/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1085 = /\-cobaltstrike/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1086 = /cobaltstrike\./ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1087 = /cobaltstrike\.store/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1088 = /cobaltstrike\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1089 = /Cobalt\-Strike\/bof_template/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1090 = /cobaltstrike_/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1091 = /CodeLoad\(shellcode\)/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1092 = /coff_definitions\.h/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1093 = /COFF_Loader\./ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1094 = /COFF_PREP_BEACON/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1095 = /CoffeeLdr.{0,1000}\sgo\s/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1096 = /CoffeeLdr\.x64\.exe/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1097 = /CoffeeLdr\.x86\.exe/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1098 = /COFFELDR_COFFELDR_H/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1099 = /COFFLoader\./ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1100 = /COFFLoader64\.exe/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1101 = /com_exec_go\(/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1102 = /com\-exec\.cna/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1103 = /common\.ReflectiveDLL/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string1104 = /common\.ReflectiveDLL/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1105 = /comnap_\#\#/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1106 = /comnode_\#\#/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1107 = /connormcgarr\/tgtdelegation/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1108 = /cookie_graber_x64\.o/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1109 = /cookie\-graber\.c/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1110 = /cookie\-graber_x64\.exe/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1111 = /Cookie\-Graber\-BOF/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1112 = /CookieProcessor\.exe/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1113 = /covid19_koadic\.profile/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1114 = /crawlLdrDllList/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1115 = /credBandit\s.{0,1000}\soutput/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1116 = /credBandit\./ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1117 = /credBanditx64/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string1118 = /CredPrompt\/CredPrompt\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1119 = /cribdragg3r\/Alaris/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1120 = /crimeware.{0,1000}\/zeus\.profile/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1121 = /crisprss\/PrintSpoofer/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1122 = /cross_s4u\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1123 = /cross_s4u\.x64\.o/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1124 = /CrossC2\sbeacon/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1125 = /CrossC2\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1126 = /crossc2_entry/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1127 = /crossc2_portscan\./ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1128 = /crossc2_serverscan\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1129 = /CrossC2Beacon/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1130 = /CrossC2Kit\./ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1131 = /CrossC2Kit\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1132 = /CrossC2Kit\.git/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1133 = /CrossC2Kit_demo/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1134 = /crossc2kit_latest/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1135 = /CrossC2Kit_Loader/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1136 = /CrossC2Listener/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1137 = /CrossC2MemScriptEng/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1138 = /CrossC2Script/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1139 = /CrossNet\.exe/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1140 = /CRTInjectAsSystem/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1141 = /CRTInjectElevated/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1142 = /CRTInjectWithoutPid/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1143 = /cs2modrewrite\.py/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1144 = /cs2nginx\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1145 = /CS\-Avoid\-killing/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1146 = /CS\-BOFs\/lsass/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1147 = /CSharpNamedPipeLoader/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1148 = /csload\.net\/.{0,1000}\/muma\./ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1149 = /csOnvps.{0,1000}teamserver/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1150 = /CS\-Remote\-OPs\-BOF/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string1151 = /CSSG_load\.cna/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1152 = /cs\-token\-vault\.git/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1153 = /cube0x0\/LdapSignCheck/ nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string1154 = /custom_payload_generator\./ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1155 = /CustomKeyboardLayoutPersistence/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1156 = /CVE_20.{0,1000}\.dll/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1157 = /cve\-20\.x64\.dll/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1158 = /cve\-20\.x86\.dll/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1159 = /DallasFR\/Cobalt\-Clip/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1160 = /darkr4y\/geacon/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1161 = /dcsync\@protonmail\.com/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1162 = /dcsyncattack\(/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1163 = /dcsyncattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1164 = /dcsyncclient\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1165 = /dcsyncclient\.py/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1166 = /DeEpinGh0st\/Erebus/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1167 = /DefaultBeaconApi/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1168 = /demo\-bof\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string1169 = /detect\-hooksx64\./ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1170 = /DisableAllWindowsSoftwareFirewalls/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1171 = /disableeventvwr\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1172 = /dll\\reflective_dll\./ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1173 = /dll_hijack_hunter/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1174 = /DLL_Imports_BOF/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1175 = /DLL_TO_HIJACK_WIN10/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1176 = /DLL\-Hijack\-Search\-Order\-BOF/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1177 = /dllinject\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1178 = /dllload\s/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1179 = /dns_beacon_beacon/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1180 = /dns_beacon_dns_idle/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1181 = /dns_beacon_dns_sleep/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1182 = /dns_beacon_dns_stager_prepend/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1183 = /dns_beacon_dns_stager_subhost/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1184 = /dns_beacon_dns_ttl/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1185 = /dns_beacon_get_A/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1186 = /dns_beacon_get_TXT/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1187 = /dns_beacon_maxdns/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1188 = /dns_beacon_ns_response/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1189 = /dns_beacon_put_metadata/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1190 = /dns_beacon_put_output/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1191 = /dns_redir\.sh\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1192 = /dns_stager_prepend/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1193 = /dns_stager_prepend/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1194 = /\'dns_stager_prepend\'/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1195 = /dns_stager_subhost/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1196 = /dns_stager_subhost/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1197 = /\'dns_stager_subhost\'/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1198 = /dns\-beacon\s/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1199 = /dnspayload\.bin/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1200 = /do_attack\(/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string1201 = /Doge\-Loader.{0,1000}xor\.go/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1202 = /douknowwhoami\?d/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1203 = /dr0op\/CrossNet/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1204 = /DReverseProxy\.git/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1205 = /DReverseServer\.go/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1206 = /drop_malleable_unknown_/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1207 = /drop_malleable_with_invalid_/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1208 = /drop_malleable_without_/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1209 = /dropper32\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1210 = /dropper64\.exe/ nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string1211 = /dtmsecurity\/bof_helper/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1212 = /Dumpert\.bin/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1213 = /Dumpert\.exe/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1214 = /Dumpert\-Aggressor/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1215 = /DumpProcessByName/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1216 = /DumpShellcode\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1217 = /dumpXor\.exe\s/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1218 = /EasyPersistent\.cna/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1219 = /elevate\sjuicypotato\s/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1220 = /elevate\sPrintspoofer/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1221 = /elevate\ssvc\-exe\s/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1222 = /ELFLoader\.c/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1223 = /ELFLoader\.h/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1224 = /ELFLoader\.out/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1225 = /empire\sAttackServers/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1226 = /EncodeGroup\/AggressiveProxy/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1227 = /EncodeGroup\/UAC\-SilentClean/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1228 = /encrypt\/encryptFile\.go/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1229 = /encrypt\/encryptUrl\.go/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1230 = /EncryptShellcode\(/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1231 = /engjibo\/NetUser/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string1232 = /EnumCLR\.exe/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1233 = /Erebus\/.{0,1000}spacerunner/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1234 = /EspressoCake\/PPLDump_BOF/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1235 = /EventAggregation\.dll\.bak/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1236 = /eventspy\.cna/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1237 = /EventSub\-Aggressor\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1238 = /EventViewerUAC\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1239 = /EventViewerUAC\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1240 = /EventViewerUAC\.x64/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1241 = /EventViewerUAC\.x86/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1242 = /EventViewerUAC_BOF/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1243 = /eventvwr_elevator/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1244 = /EVUAC\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1245 = /ewby\/Mockingjay_BOF/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1246 = /example\-bof\.sln/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1247 = /execmethod.{0,1000}PowerPick/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1248 = /execmethod.{0,1000}PowerShell/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1249 = /execute_bof\s/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1250 = /execute\-assembly\s.{0,1000}\.exe\s/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1251 = /executepersistence/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1252 = /Export\-PowerViewCSV/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1253 = /extract_reflective_loader/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1254 = /Fiesta\sExploit\sKit/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1255 = /FileControler\/FileControler_x64\.dll/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1256 = /FileControler\/FileControler_x86\.dll/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1257 = /find_payload\(/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1258 = /findgpocomputeradmin/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1259 = /Find\-GPOComputerAdmin/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1260 = /Find\-InterestingDomainAcl/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1261 = /findinterestingdomainsharefile/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1262 = /Find\-InterestingDomainShareFile/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1263 = /findlocaladminaccess/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1264 = /findlocaladminaccess/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1265 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1266 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1267 = /FindModule\s.{0,1000}\.dll/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1268 = /FindObjects\-BOF/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1269 = /FindProcessTokenAndDuplicate/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1270 = /FindProcHandle\s.{0,1000}lsass/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1271 = /Firewall_Walker_BOF/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1272 = /fishing_with_hollowing/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1273 = /foreign_access\.cna/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1274 = /foreign_lsass\s.{0,1000}\s/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1275 = /foreign_lsass\.c/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1276 = /foreign_lsass\.x64/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1277 = /foreign_lsass\.x86/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1278 = /\-\-format\-string\sziiiiizzzb\s.{0,1000}\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1279 = /\-\-format\-string\sziiiiizzzib\s/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1280 = /fortra\/No\-Consolation/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1281 = /fucksetuptools/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string1282 = /FuckThatPacker\./ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1283 = /FunnyWolf\/pystinger/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1284 = /fw_walk\sdisable/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1285 = /G0ldenGunSec\/GetWebDAVStatus/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1286 = /GadgetToJScript\.exe\s\-a\s/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1287 = /Gality369\/CS\-Loader/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1288 = /gather\/keylogger/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1289 = /geacon.{0,1000}\/cmd\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1290 = /genCrossC2\./ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1291 = /generate_beacon/ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1292 = /generate\-rotating\-beacon\./ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1293 = /GeorgePatsias\/ScareCrow/ nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string1294 = /get_BeaconHealthCheck_settings/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1295 = /get_dns_dnsidle/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1296 = /get_dns_sleep/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1297 = /get_password_policy\.x64\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1298 = /get_password_policy\.x86\./ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1299 = /get_post_ex_pipename_list/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1300 = /get_post_ex_spawnto_x/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1301 = /get_process_inject_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1302 = /get_process_inject_bof_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1303 = /get_process_inject_execute/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1304 = /get_stage_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1305 = /get_stage_magic_mz_64/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1306 = /get_stage_magic_mz_86/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1307 = /get_stage_magic_pe/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1308 = /get_virtual_Hook_address/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1309 = /getAggressorClient/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1310 = /Get\-BeaconAPI/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1311 = /Get\-CachedRDPConnection/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1312 = /getCrossC2Beacon/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1313 = /getCrossC2Site/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1314 = /getdomainspnticket/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1315 = /Get\-DomainSPNTicket/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1316 = /getexploitablesystem/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1317 = /Get\-ExploitableSystem/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1318 = /GetHijackableDllName/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1319 = /GetNTLMChallengeBase64/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1320 = /GetShellcode\(/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1321 = /GetWebDAVStatus\.csproj/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1322 = /GetWebDAVStatus\.sln/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1323 = /GetWebDAVStatus_DotNet/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1324 = /GetWebDAVStatus_x64\.o/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1325 = /getwmiregcachedrdpconnection/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1326 = /Get\-WMIRegCachedRDPConnection/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1327 = /getwmireglastloggedon/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1328 = /Get\-WMIRegLastLoggedOn/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1329 = /gexplorer\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1330 = /GhostPack\/Koh/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1331 = /github.{0,1000}\/MoveKit\.git/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1332 = /github\.com\/k8gege/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1333 = /github\.com\/rasta\-mouse\// nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1334 = /github\.com\/SpiderLabs\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1335 = /gloxec\/CrossC2/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1336 = /go_shellcode_encode\.py/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1337 = /go\-shellcode\.py/ nocase ascii wide
        // Description: generate shellcode
        // Reference: https://github.com/fcre1938/goShellCodeByPassVT
        $string1338 = /goShellCodeByPassVT/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1339 = /hackbrowersdata\.cna/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1340 = /hack\-browser\-data\// nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1341 = /handlekatz\.x64\./ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1342 = /handlekatz_bof\./ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1343 = /Hangingsword\/HouQing/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1344 = /hd\-launch\-cmd\s/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1345 = /headers\/exploit\.h/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1346 = /headers\/HandleKatz\.h/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1347 = /Henkru\/cs\-token\-vault/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1348 = /Hidden\.Desktop\.mp4/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1349 = /HiddenDesktop\s.{0,1000}\s/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1350 = /HiddenDesktop\./ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1351 = /HiddenDesktop\.x64\.bin/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1352 = /HiddenDesktop\.x86\.bin/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1353 = /HiddenDesktop\.zip/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1354 = /hijack_hunter\s/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1355 = /hijack_remote_thread/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1356 = /HiveJack\-Console\.exe/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string1357 = /hollow\s.{0,1000}\.exe\s.{0,1000}\.bin/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1358 = /hollower\.Hollow\(/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1359 = /houqingv1\.0\.zip/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1360 = /html\/js\/beacons\.js/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1361 = /http.{0,1000}\/zha0gongz1/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1362 = /http.{0,1000}:3200\/manjusaka/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1363 = /http.{0,1000}:801\/bq1iFEP2/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1364 = /http:\/\/127\.0\.0\.1:8000\/1\.jpg/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1365 = /http_stager_client_header/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1366 = /http_stager_server_append/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1367 = /http_stager_server_header/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1368 = /http_stager_server_prepend/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1369 = /http_stager_uri_x64/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1370 = /http_stager_uri_x86/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1371 = /http1\.x64\.bin/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1372 = /http1\.x64\.dll/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1373 = /httpattack\.py/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1374 = /httppayload\.bin/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1375 = /http\-redwarden/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1376 = /httprelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1377 = /httprelayserver\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1378 = /\'http\-stager\'/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1379 = /HVNC\sServer\.exe/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1380 = /HVNC\\\sServer/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string1381 = /IcebreakerSecurity\/DelegationBOF/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1382 = /IcebreakerSecurity\/PersistBOF/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1383 = /imapattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1384 = /imaprelayclient\.py/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1385 = /impacket\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1386 = /ImpersonateLocalService/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1387 = /import\spe\.OBJExecutable/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1388 = /include\sbeacon\.h/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1389 = /include\sinjection\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1390 = /inject\-amsiBypass\s/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1391 = /inject\-amsiBypass\./ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1392 = /inject\-assembly\s/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1393 = /inject\-assembly\.cna/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1394 = /injectassembly\.x64\.bin/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1395 = /injectassembly\.x64\.o/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1396 = /injectEtwBypass/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1397 = /InjectShellcode/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1398 = /inline\-execute\s/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1399 = /inline\-execute.{0,1000}whereami\.x64/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1400 = /InlineExecute\-Assembly/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string1401 = /InlineWhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string1402 = /InlineWhispers2/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1403 = /install\simpacket/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1404 = /InvokeBloodHound/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1405 = /Invoke\-Bof\s/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1406 = /Invoke\-Bof\.ps1/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1407 = /invokechecklocaladminaccess/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1408 = /Invoke\-CheckLocalAdminAccess/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1409 = /invokeenumeratelocaladmin/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1410 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1411 = /Invoke\-EnvBypass\./ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1412 = /Invoke\-EventVwrBypass/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1413 = /invokefilefinder/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1414 = /Invoke\-FileFinder/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string1415 = /Invoke\-HostEnum\s\-/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1416 = /invokekerberoast/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1417 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1418 = /Invoke\-Phant0m/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1419 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1420 = /invokeprocesshunter/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1421 = /Invoke\-ProcessHunter/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1422 = /invokereverttoself/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1423 = /Invoke\-RevertToSelf/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1424 = /invokesharefinder/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1425 = /Invoke\-ShareFinder/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1426 = /invokestealthuserhunter/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1427 = /Invoke\-StealthUserHunter/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1428 = /invokeuserhunter/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1429 = /Invoke\-UserHunter/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1430 = /Invoke\-WScriptBypassUAC/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1431 = /jas502n\/bypassAV/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1432 = /java\s\-jar\sBeaconTool\.jar/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1433 = /Job\skilled\sand\sconsole\sdrained/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1434 = /jquery\-c2\..{0,1000}\.profile/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1435 = /jump\spsexec_psh/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1436 = /jump\spsexec64/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1437 = /jump\swinrm\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1438 = /jump\swinrm/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1439 = /jump\-exec\sscshell/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1440 = /K8_CS_.{0,1000}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1441 = /k8gege\.org\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1442 = /k8gege\/Ladon/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1443 = /K8Ladon\.sln/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1444 = /KaliLadon\./ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1445 = /KBDPAYLOAD\.dll/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1446 = /kdstab\s.{0,1000}\s\/CHECK/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1447 = /kdstab\s.{0,1000}\s\/CLOSE/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1448 = /kdstab\s.{0,1000}\s\/DRIVER/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1449 = /kdstab\s.{0,1000}\s\/KILL/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1450 = /kdstab\s.{0,1000}\s\/LIST/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1451 = /kdstab\s.{0,1000}\s\/NAME/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1452 = /kdstab\s.{0,1000}\s\/PID/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1453 = /kdstab\s.{0,1000}\s\/SERVICE/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1454 = /kdstab\s.{0,1000}\s\/STRIP/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1455 = /kdstab\s.{0,1000}\s\/UNLOAD/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1456 = /kdstab\.cna/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1457 = /kerberoasting\.x64/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1458 = /Kerberos\sabuse\s\(kerbeus\sBOF\)/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1459 = /kerberos.{0,1000}\.kirbi/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1460 = /Kerbeus\s.{0,1000}\sby\sRalfHacker/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1461 = /kerbeus_cs\.cna/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1462 = /kerbeus_havoc\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1463 = /Kerbeus\-BOF\-main/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1464 = /kernelcallbacktable\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1465 = /kernelcallbacktable\.x64/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1466 = /kernelcallbacktable\.x86/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1467 = /kernelcallbacktable\.x86/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1468 = /KernelMii\.cna/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1469 = /KernelMii\.x64\.exe/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1470 = /KernelMii\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1471 = /KernelMii\.x86\.exe/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1472 = /KernelMii\.x86\.o/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1473 = /killdefender\scheck/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1474 = /killdefender\skill/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1475 = /KillDefender\.x64/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1476 = /KillDefender\.x64\./ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1477 = /KillDefender_BOF/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1478 = /killdefender_bof/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1479 = /kirbi\.tickets/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1480 = /koh\sfilter\sadd\sSID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1481 = /koh\sfilter\slist/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1482 = /koh\sfilter\sremove\sSID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1483 = /koh\sfilter\sreset/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1484 = /koh\sgroups\sLUID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1485 = /koh\simpersonate\sLUID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1486 = /koh\srelease\sall/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1487 = /koh\srelease\sLUID/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1488 = /Koh\.exe\scapture/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1489 = /Koh\.exe\slist/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1490 = /Koh\.exe\smonitor/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1491 = /krb_asktgs\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1492 = /krb_asktgt\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1493 = /krb_asreproasting/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1494 = /krb_changepw\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1495 = /krb_cross_s4u\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1496 = /krb_describe\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1497 = /krb_dump\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1498 = /krb_hash\s\/password/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1499 = /krb_klist\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1500 = /krb_ptt\s\/ticket:/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1501 = /krb_purge\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1502 = /krb_renew\s\/ticket:/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1503 = /krb_s4u\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1504 = /krb_tgtdeleg\s\// nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1505 = /krb_tgtdeleg\(.{0,1000}\)/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1506 = /krb_triage\s\// nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1507 = /krb5\/kerberosv5\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1508 = /krbasktgt\s\// nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1509 = /krbcredccache\.py/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string1510 = /kyleavery\/AceLdr/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1511 = /kyleavery\/inject\-assembly/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1512 = /Ladon\s.{0,1000}\sAllScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1513 = /Ladon\s.{0,1000}\sCiscoScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1514 = /Ladon\s.{0,1000}\sOnlineIP/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1515 = /Ladon\s.{0,1000}\sOnlinePC/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1516 = /Ladon\s.{0,1000}\sOsScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1517 = /Ladon\s.{0,1000}\sOxidScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1518 = /Ladon\s.{0,1000}\.txt\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1519 = /Ladon\s.{0,1000}DeBase64/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1520 = /Ladon\s.{0,1000}FtpScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1521 = /Ladon\s.{0,1000}LdapScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1522 = /Ladon\s.{0,1000}SMBGhost/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1523 = /Ladon\s.{0,1000}SmbHashScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1524 = /Ladon\s.{0,1000}SmbScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1525 = /Ladon\s.{0,1000}SshScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1526 = /Ladon\s.{0,1000}TomcatScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1527 = /Ladon\s.{0,1000}VncScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1528 = /Ladon\s.{0,1000}WebScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1529 = /Ladon\s.{0,1000}WinrmScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1530 = /Ladon\s.{0,1000}WmiHashScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1531 = /Ladon\s.{0,1000}WmiScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1532 = /Ladon\sActiveAdmin/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1533 = /Ladon\sActiveGuest/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1534 = /Ladon\sAdiDnsDump\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1535 = /Ladon\sat\sc:/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1536 = /Ladon\sAtExec/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1537 = /Ladon\sAutoRun/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1538 = /Ladon\sBadPotato/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1539 = /Ladon\sBypassUAC/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1540 = /Ladon\sCheckDoor/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1541 = /Ladon\sClslog/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1542 = /Ladon\sCmdDll\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1543 = /Ladon\scmdline/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1544 = /Ladon\sCVE\-/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1545 = /Ladon\sDirList/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1546 = /Ladon\sDraytekExp/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1547 = /Ladon\sDumpLsass/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1548 = /Ladon\sEnableDotNet/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1549 = /Ladon\sEnumProcess/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1550 = /Ladon\sEnumShare/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1551 = /Ladon\sExploit/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1552 = /Ladon\sFindIP\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1553 = /Ladon\sFirefoxCookie/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1554 = /Ladon\sFirefoxHistory/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1555 = /Ladon\sFirefoxPwd/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1556 = /Ladon\sForExec\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1557 = /Ladon\sFtpDownLoad\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1558 = /Ladon\sFtpServer\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1559 = /Ladon\sGetDomainIP/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1560 = /Ladon\sgethtml\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1561 = /Ladon\sGetPipe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1562 = /Ladon\sGetSystem/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1563 = /Ladon\sIISdoor/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1564 = /Ladon\sIISpwd/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1565 = /Ladon\sMssqlCmd\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1566 = /Ladon\snetsh\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1567 = /Ladon\snoping\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1568 = /Ladon\sOpen3389/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1569 = /Ladon\sPowerCat\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1570 = /Ladon\sPrintNightmare/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1571 = /Ladon\spsexec/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1572 = /Ladon\sQueryAdmin/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1573 = /Ladon\sRdpHijack/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1574 = /Ladon\sReadFile\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1575 = /Ladon\sRegAuto/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1576 = /Ladon\sReverseHttps/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1577 = /Ladon\sReverseTcp\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1578 = /Ladon\sRevShell\-/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1579 = /Ladon\sRunas/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1580 = /Ladon\sRunPS\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1581 = /Ladon\ssc\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1582 = /Ladon\sSetSignAuth/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1583 = /Ladon\sSmbExec\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1584 = /Ladon\sSniffer/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1585 = /Ladon\sSshExec\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1586 = /Ladon\sSweetPotato/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1587 = /Ladon\sTcpServer\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1588 = /Ladon\sUdpServer/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1589 = /Ladon\sWebShell/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1590 = /Ladon\swhoami/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1591 = /Ladon\sWifiPwd/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1592 = /Ladon\swmiexec/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1593 = /Ladon\sWmiExec2\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1594 = /Ladon\sXshellPwd/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1595 = /Ladon\sZeroLogon/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1596 = /Ladon40\sBypassUAC/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1597 = /Ladon911.{0,1000}\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1598 = /Ladon911\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1599 = /Ladon911_.{0,1000}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1600 = /LadonExp\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1601 = /LadonGUI\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1602 = /LadonLib\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1603 = /LadonStudy\.exe/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1604 = /lastpass\.x86/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1605 = /lastpass\/process_lp_files\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1606 = /ldap_shell\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1607 = /ldapattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1608 = /ldaprelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1609 = /LdapSignCheck\.exe/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1610 = /LdapSignCheck\.Natives/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1611 = /LdapSignCheck\.sln/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1612 = /ldapsigncheck\.x64\./ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1613 = /ldapsigncheck\.x86\./ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1614 = /LetMeOutSharp\./ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1615 = /libs\/bofalloc/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1616 = /libs\/bofentry/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1617 = /libs\/bofhelper/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1618 = /LiquidSnake\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1619 = /llsrpc_\#\#/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1620 = /load\saggressor\sscript/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string1621 = /load_sc\.exe\s.{0,1000}\.bin/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1622 = /Load\-BeaconParameters/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1623 = /Load\-Bof\(/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1624 = /loader\/loader\/loader\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1625 = /localS4U2Proxy\.tickets/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1626 = /logToBeaconLog/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1627 = /lsarpc_\#\#/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1628 = /Magnitude\sExploit\sKit/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1629 = /main_air_service\-probes\.go/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1630 = /main_pro_service\-probes\.go/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1631 = /makebof\.bat/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string1632 = /Malleable\sC2\sFiles/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1633 = /Malleable\sPE\/Stage/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1634 = /malleable_redirector\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1635 = /malleable_redirector_hidden_api_endpoint/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1636 = /Malleable\-C2\-Profiles/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1637 = /Malleable\-C2\-Randomizer/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1638 = /Malleable\-C2\-Randomizer/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1639 = /malleable\-redirector\-config/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string1640 = /mandllinject\s/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1641 = /mdsecactivebreach\/CACTUSTORCH/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1642 = /med0x2e\/SigFlip/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1643 = /memreader\s.{0,1000}access_token/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1644 = /MemReader_BoF\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1645 = /meterpreter\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1646 = /metsrv\.dll/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1647 = /mgeeky\/RedWarden/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1648 = /mimipenguin\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1649 = /mimipenguin\.so/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1650 = /mimipenguin_x32\.so/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1651 = /minidump_add_memory_block/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1652 = /minidump_add_memory64_block/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1653 = /minidumpwritedump/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1654 = /MiniDumpWriteDump/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1655 = /miscbackdoorlnkhelp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1656 = /Mockingjay_BOF\.sln/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1657 = /Mockingjay_BOF\-main/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1658 = /mojo_\#\#/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1659 = /moonD4rk\/HackBrowserData/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1660 = /MoveKit\-master\.zip/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1661 = /move\-msbuild\s.{0,1000}\shttp\smove\.csproj/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1662 = /move\-pre\-custom\-file\s.{0,1000}\.exe\s/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string1663 = /msfvemonpayload/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1664 = /mssqlattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1665 = /mssqlrelayclient\.py/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1666 = /my_dump_my_pe/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1667 = /needle_sift\.x64/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1668 = /needlesift\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1669 = /netero1010\/Quser\-BOF/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1670 = /netero1010\/ServiceMove\-BOF/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1671 = /netlogon_\#\#/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1672 = /netuser_enum/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1673 = /netview_enum/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1674 = /NoApiUser\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1675 = /noconsolation\s\/tmp\// nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1676 = /noconsolation\s\-\-local\s.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1677 = /noconsolation\s\-\-local\s.{0,1000}powershell\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1678 = /No\-Consolation\.cna/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1679 = /NoConsolation\.x64\.o/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1680 = /NoConsolation\.x86\.o/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1681 = /No\-Consolation\-main/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1682 = /normal\/randomized\.profile/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1683 = /ntcreatethread\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1684 = /ntcreatethread\.x86/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1685 = /oab\-parse\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1686 = /obscuritylabs\/ase:latest/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1687 = /obscuritylabs\/RAI\// nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1688 = /Octoberfest7\/KDStab/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1689 = /OG\-Sadpanda\/SharpCat/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string1690 = /OG\-Sadpanda\/SharpSword/ nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string1691 = /OG\-Sadpanda\/SharpZippo/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1692 = /On_Demand_C2\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1693 = /On\-Demand_C2_BOF\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1694 = /OnDemandC2Class\.cs/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1695 = /openBeaconBrowser/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1696 = /openBeaconBrowser/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1697 = /openBeaconConsole/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1698 = /openBeaconConsole/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1699 = /openBypassUACDialog/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1700 = /openBypassUACDialog/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1701 = /openGoldenTicketDialog/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1702 = /openKeystrokeBrowser/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1703 = /openPayloadGenerator/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1704 = /openPayloadGeneratorDialog/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1705 = /openPayloadHelper/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1706 = /openPortScanner/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1707 = /openPortScanner/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1708 = /openSpearPhishDialog/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1709 = /openWindowsExecutableStage/ nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string1710 = /optiv\/Registry\-Recon/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1711 = /optiv\/ScareCrow/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1712 = /Outflank\-Dumpert\./ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1713 = /outflanknl\/Recon\-AD/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string1714 = /outflanknl\/Spray\-AD/ nocase ascii wide
        // Description: s
        // Reference: https://github.com/outflanknl/WdToggle
        $string1715 = /outflanknl\/WdToggle/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1716 = /Outflank\-Recon\-AD/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1717 = /output\/html\/data\/beacons\.json/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1718 = /output\/payloads\// nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1719 = /parse_aggressor_properties/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1720 = /parse_shellcode/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1721 = /patchAmsiOpenSession/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1722 = /payload_bootstrap_hint/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1723 = /payload_local/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1724 = /payload_scripts\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1725 = /payload_scripts\/sleepmask/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1726 = /payload_section\.cpp/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1727 = /payload_section\.hpp/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1728 = /payloadgenerator\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1729 = /Perform\sAS\-REP\sroasting/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1730 = /PersistBOF\.cna/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1731 = /PersistenceBOF\.c/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1732 = /PersistenceBOF\.exe/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1733 = /persist\-ice\-junction\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1734 = /persist\-ice\-monitor\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1735 = /persist\-ice\-shortcut\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1736 = /persist\-ice\-time\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1737 = /persist\-ice\-xll\.o/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1738 = /Phant0m_cobaltstrike/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1739 = /\'pipename_stager\'/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1740 = /Pitty\sTiger\sRAT/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1741 = /\-pk8gege\.org/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1742 = /pkexec64\.tar\.gz/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1743 = /plug_getpass_nps\.dll/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1744 = /plug_katz_nps\.exe/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1745 = /plug_qvte_nps\.exe/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1746 = /PortBender\sbackdoor/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1747 = /PortBender\sredirect/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1748 = /PortBender\.cna/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1749 = /PortBender\.cpp/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1750 = /portbender\.dll/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1751 = /PortBender\.exe/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1752 = /PortBender\.h/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1753 = /PortBender\.sln/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1754 = /PortBender\.zip/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1755 = /portscan_result\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1756 = /portscan386\s/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1757 = /portscan64\s/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1758 = /post_ex_amsi_disable/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1759 = /post_ex_keylogger/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1760 = /post_ex_obfuscate/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1761 = /Post_EX_Process_Name/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1762 = /post_ex_smartinject/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1763 = /post_ex_spawnto_x64/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1764 = /post_ex_spawnto_x86/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1765 = /powershell_encode_oneliner/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1766 = /powershell_encode_oneliner/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1767 = /powershell_encode_stager/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1768 = /powershell_encode_stager/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1769 = /powershell\-import\s.{0,1000}\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1770 = /PowerView3\-Aggressor/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1771 = /ppenum\.c/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1772 = /ppenum\.exe/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1773 = /ppenum\.x64\./ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1774 = /ppenum\.x86\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1775 = /ppl_dump\.x64/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1776 = /ppldump\s/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1777 = /PPLDump_BOF\./ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1778 = /pplfault\.cna/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1779 = /PPLFaultDumpBOF/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1780 = /PPLFaultPayload\.dll/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1781 = /PPLFaultTemp/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1782 = /praetorian\.antihacker/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1783 = /praetorian\-inc\/PortBender/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1784 = /prepareResponseForHiddenAPICall/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1785 = /PrintSpoofer\-/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1786 = /PrintSpoofer\./ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1787 = /process_imports\.cna/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1788 = /process_imports\.x64/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1789 = /process_imports_api\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1790 = /process_inject_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1791 = /process_inject_bof_allocator/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1792 = /process_inject_bof_reuse_memory/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1793 = /process_inject_execute/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1794 = /process_inject_min_alloc/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1795 = /process_inject_startrwx/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1796 = /Process_Inject_Struct/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1797 = /process_inject_transform_x/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1798 = /process_inject_userwx/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1799 = /process_protection_enum\s/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1800 = /process_protection_enum.{0,1000}\.dmp/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1801 = /process_protection_enum\./ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1802 = /Process_Protection_Level_BOF\./ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1803 = /Process_Protection_Level_BOF\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1804 = /ProcessDestroy\.x64/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1805 = /ProcessDestroy\.x64\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1806 = /ProcessDestroy\.x86/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1807 = /ProcessDestroy\.x86\./ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1808 = /process\-inject\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1809 = /processinject_min_alloc/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1810 = /ProgIDsUACBypass\./ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1811 = /Proxy\sShellcode\sHandler/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1812 = /proxychains.{0,1000}scshell/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1813 = /proxyshellcodeurl/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1814 = /PSconfusion\.py/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1815 = /PSEXEC_PSH\s/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/pureqh/bypassAV
        $string1816 = /pureqh\/bypassAV/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1817 = /pwn1sher\/CS\-BOFs/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1818 = /pycobalt\./ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1819 = /pycobalt\/aggressor/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1820 = /pycobalt_debug_on/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1821 = /pycobalt_path/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1822 = /pycobalt_python/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1823 = /pycobalt_timeout/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1824 = /pyMalleableC2/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1825 = /pystinger_for_darkshadow/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1826 = /python\sscshell/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1827 = /python2\?\?\/generator\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1828 = /python2\?\?\/PyLoader\.py/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1829 = /python3\sscshell/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1830 = /python3\?\?\/generator\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1831 = /python3\?\?\/PyLoader\.py/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1832 = /QUAPCInjectAsSystem/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1833 = /QUAPCInjectElevated/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1834 = /QUAPCInjectFakecmd/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1835 = /QUAPCInjectFakecmd/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1836 = /QUAPCInjectWithoutPid/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1837 = /quser\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1838 = /quser\.x86\.o/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1839 = /QXh4OEF4eDhBeHg4QXh4OA\=\=/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1840 = /RAI\/ase_docker/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1841 = /rai\-attack\-servers\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1842 = /rai\-redirector\-dns/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1843 = /rai\-redirector\-http/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1844 = /RalfHacker\/Kerbeus\-BOF/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1845 = /random_c2_profile/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1846 = /random_c2profile\./ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1847 = /random_user_agent\.params/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1848 = /random_user_agent\.user_agent/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1849 = /rasta\-mouse\/PPEnum/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1850 = /rasta\-mouse\/TikiTorch/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1851 = /rdi_net_user\.cpp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1852 = /rdphijack\.x64/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1853 = /rdphijack\.x86/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1854 = /RDPHijack\-BOF/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1855 = /RdpThief\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1856 = /read_cs_teamserver/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1857 = /Recon\-AD\-.{0,1000}\.dll/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1858 = /Recon\-AD\-.{0,1000}\.sln/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1859 = /Recon\-AD\-.{0,1000}\.vcxproj/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1860 = /Recon\-AD\-AllLocalGroups/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1861 = /Recon\-AD\-Domain/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1862 = /Recon\-AD\-LocalGroups/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1863 = /Recon\-AD\-SPNs/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1864 = /Recon\-AD\-Users\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1865 = /redelk_backend_name_c2/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1866 = /redelk_backend_name_decoy/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1867 = /Red\-Team\-Infrastructure\-Wiki\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1868 = /RedWarden\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1869 = /RedWarden\.test/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1870 = /redwarden_access\.log/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1871 = /redwarden_redirector\.log/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1872 = /reflective_dll\.dll/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1873 = /reflective_dll\.x64\.dll/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1874 = /ReflectiveDll\.x64\.dll/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1875 = /ReflectiveDll\.x86\.dll/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1876 = /Reflective\-HackBrowserData/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1877 = /Remote\/lastpass\/lastpass\.x86\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1878 = /Remote\/setuserpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1879 = /Remote\/shspawnas/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1880 = /Remote\/suspendresume\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1881 = /remote\-exec\s.{0,1000}jump\s/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1882 = /remotereg\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1883 = /replace_key_iv_shellcode/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1884 = /RiccardoAncarani\/BOFs/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1885 = /RiccardoAncarani\/LiquidSnake/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string1886 = /RiccardoAncarani\/TaskShell/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1887 = /rkervella\/CarbonMonoxide/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1888 = /rookuu\/BOFs\// nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1889 = /rpcattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1890 = /rpcrelayclient\.py/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1891 = /rsmudge\/ElevateKit/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1892 = /runasadmin\suac\-cmstplua/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1893 = /runasadmin\suac\-token\-duplication/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1894 = /RunOF\.exe\s\-/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1895 = /RunOF\.Internals/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1896 = /rustbof\.cna/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1897 = /rvrsh3ll\/BOF_Collection/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1898 = /rxwx\/cs\-rdll\-ipc\-example/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1899 = /s4u\.x64\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1900 = /s4u\.x64\.o/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1901 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1902 = /SamAdduser\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1903 = /samr_\#\#/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1904 = /ScareCrow.{0,1000}\s\-encryptionmode\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1905 = /ScareCrow.{0,1000}\s\-Evasion/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1906 = /ScareCrow.{0,1000}\s\-Exec/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1907 = /ScareCrow.{0,1000}\s\-injection/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1908 = /ScareCrow.{0,1000}\s\-Loader\s.{0,1000}\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1909 = /ScareCrow.{0,1000}\s\-noamsi/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1910 = /ScareCrow.{0,1000}\s\-noetw/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1911 = /ScareCrow.{0,1000}\s\-obfu/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1912 = /ScareCrow.{0,1000}_darwin_amd64/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1913 = /ScareCrow.{0,1000}_windows_amd64\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1914 = /ScareCrow.{0,1000}KnownDLL/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1915 = /ScareCrow.{0,1000}ProcessInjection/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1916 = /ScareCrow\.cna/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1917 = /ScareCrow\/Cryptor/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1918 = /ScareCrow\/limelighter/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1919 = /ScareCrow\/Loader/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1920 = /ScareCrow\/Utils/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1921 = /schshell\.cna/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1922 = /schtask_callback/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1923 = /schtasks_elevator/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1924 = /schtasks_exploit\s/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1925 = /ScRunBase32\.exe/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1926 = /ScRunBase32\.py/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1927 = /ScRunBase64\.exe/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1928 = /ScRunBase64\.py/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1929 = /scshell.{0,1000}XblAuthManager/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1930 = /SCShell\.exe/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1931 = /scshell\.py/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1932 = /scshellbof\.c/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1933 = /scshellbof\.o/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1934 = /scshellbofx64/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1935 = /searchsploit_rc/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1936 = /Seatbelt\.exe/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1937 = /sec\-inject\s/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1938 = /secinject\.cna/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1939 = /secinject\.git/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1940 = /secinject\.x64/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1941 = /secinject\.x86/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1942 = /secinject\/src/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1943 = /secretsdump\..{0,1000}\.pyc/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1944 = /secretsdump\.py/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1945 = /sec\-shinject\s/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1946 = /self_delete\.x64\.o/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1947 = /Self_Deletion_BOF/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1948 = /send_shellcode_via_pipe/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1949 = /send_shellcode_via_pipe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1950 = /serverscan\.linux\.elf/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1951 = /serverscan\.linux\.so/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1952 = /serverScan\.win\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1953 = /serverscan_386\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1954 = /ServerScan_Air_.{0,1000}\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1955 = /ServerScan_Air_.{0,1000}_amd64/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1956 = /ServerScan_Air_.{0,1000}_i386/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1957 = /serverscan_air\-probes\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1958 = /serverscan_amd64\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1959 = /ServerScan_Pro_.{0,1000}\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1960 = /ServerScan_Pro_.{0,1000}_amd64/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1961 = /ServerScan_Pro_.{0,1000}_i386/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1962 = /serverscan64\s/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1963 = /serverscan64\s.{0,1000}tcp/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1964 = /serverscan86\s/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1965 = /servicemove.{0,1000}hid\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1966 = /set\shosts_stage/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1967 = /set\skeylogger/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1968 = /set\sobfuscate\s/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1969 = /set\spipename\s/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1970 = /set\ssmartinject/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1971 = /set\suserwx/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1972 = /setc_webshell/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1973 = /setLoaderFlagZero/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1974 = /setthreadcontext\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1975 = /setthreadcontext\.x86/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1976 = /setup_obfuscate_xor_key/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1977 = /setup_reflective_loader/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1978 = /seventeenman\/CallBackDump/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1979 = /ShadowUser\/scvhost\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1980 = /Sharp\sCompile/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string1981 = /SharpCalendar\.exe/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1982 = /SharpCat\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1983 = /sharpcompile.{0,1000}\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1984 = /sharpCompileHandler/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1985 = /SharpCompileServer/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1986 = /SharpCompileServer\.exe/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1987 = /SharpCradle.{0,1000}logonpasswords/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1988 = /SharpCradle\.exe/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string1989 = /SharpEventLoader/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string1990 = /SharpEventPersist/ nocase ascii wide
        // Description: Read Excel Spreadsheets (XLS/XLSX) using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpExcelibur
        $string1991 = /SharpExcelibur/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1992 = /sharp\-exec\s/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1993 = /sharp\-fexec\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1994 = /SharpGen\.dll/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1995 = /sharpgen\.enable_cache/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1996 = /sharpgen\.py/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1997 = /sharpgen\.set_location/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1998 = /Sharp\-HackBrowserData/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1999 = /SharpHound\.cna/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2000 = /SharpHound\.exe/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2001 = /SharpHound\.ps1/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2002 = /Sharphound2\./ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2003 = /Sharphound\-Aggressor/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2004 = /SharpSCShell/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string2005 = /SharpSploitConsole_x/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string2006 = /SharpStay\.exe/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string2007 = /SharpSword\.exe/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2008 = /SharpZeroLogon/ nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string2009 = /SharpZippo\.exe/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string2010 = /shell\.exe\s\-s\spayload\.txt/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string2011 = /Shellcode_encryption\.exe/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string2012 = /shellcode_generator\./ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string2013 = /shellcode_generator_help\.html/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string2014 = /ShellCode_Loader\.py/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2015 = /shellcode20\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2016 = /shellcode30\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2017 = /shellcode35\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2018 = /shellcode40\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2019 = /shspawn\sx64\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2020 = /shspawn\sx86\s/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2021 = /SigFlip\.exe\s\-/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2022 = /SigFlip\.WinTrustData/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2023 = /SigInject\s.{0,1000}\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2024 = /Sigloader\s.{0,1000}\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2025 = /SigLoader\/sigloader\.c/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2026 = /sigwhatever\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string2027 = /Silent\sLsass\sDump/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string2028 = /silentLsassDump/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2029 = /\-Situational\-Awareness\-BOF/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2030 = /sleep_python_bridge\.sleepy/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2031 = /sleep_python_bridge\.striker/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2032 = /sleepmask\.x64\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2033 = /sleepmask\.x86\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2034 = /sleepmask_pivot\.x64\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2035 = /sleepmask_pivot\.x86\.o/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2036 = /smb_pipename_stager/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2037 = /smbattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2038 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2039 = /smbrelayserver\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2040 = /smtprelayclient\.py/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2041 = /socky\swhoami/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2042 = /SourcePoint.{0,1000}Loader\.go/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2043 = /source\-teamserver\.sh/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string2044 = /spawn\/runshellcode/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2045 = /SpawnTheThing\(/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2046 = /spawnto\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2047 = /\'spawnto_x64\'/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2048 = /\'spawnto_x86\'/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2049 = /spoolss_\#\#/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2050 = /spoolsystem\sinject/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2051 = /spoolsystem\sspawn/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2052 = /spoolsystem\.cna/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2053 = /SpoolTrigger\.x64\.dl/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2054 = /SpoolTrigger\.x64\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2055 = /SpoolTrigger\.x86\.dl/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2056 = /SpoolTrigger\.x86\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2057 = /SpoolTrigger\\SpoolTrigger\./ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2058 = /Spray\-AD\s/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2059 = /Spray\-AD\.cna/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2060 = /Spray\-AD\.dll/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2061 = /Spray\-AD\.exe/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2062 = /Spray\-AD\.sln/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2063 = /Spray\-AD\\Spray\-AD/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2064 = /src\/Remote\/chromeKey\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2065 = /src\/Remote\/lastpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2066 = /src\/Remote\/sc_config\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2067 = /src\/Remote\/sc_create\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2068 = /src\/Remote\/sc_delete\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2069 = /src\/Remote\/sc_start\// nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2070 = /Src\/Spray\-AD/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2071 = /src\/zerologon\.c/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string2072 = /src\\unhook\.c/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2073 = /srvsvc_\#\#/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2074 = /stage\.obfuscate/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2075 = /stage_smartinject/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2076 = /stage_transform_x64_prepend/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2077 = /stage_transform_x64_strrep1/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2078 = /stage_transform_x86_prepend/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2079 = /stage_transform_x86_strrep1/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string2080 = /stageless\spayload/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2081 = /stager_bind_pipe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2082 = /stager_bind_pipe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2083 = /stager_bind_tcp/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2084 = /stager_bind_tcp/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2085 = /start\sstinger\s/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2086 = /StartProcessFake\(/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2087 = /static_syscalls_apc_spawn\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2088 = /static_syscalls_apc_spawn/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2089 = /static_syscalls_dump/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2090 = /StayKit\.cna/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2091 = /StayKit\.exe/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2092 = /StayKit\.git/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2093 = /steal_token\(/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2094 = /steal_token_access_mask/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2095 = /stinger_client\s\-/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2096 = /stinger_client\.py/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2097 = /stinger_server\.exe/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2098 = /strip_bof\.ps1/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2099 = /strip\-bof\s\-Path\s/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2100 = /suspendresume\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2101 = /suspendresume\.x86\./ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2102 = /SW2_GetSyscallNumber/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2103 = /SW2_HashSyscall/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2104 = /SW2_PopulateSyscallList/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2105 = /SW2_RVA2VA/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2106 = /SwampThing\.exe/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2107 = /SweetPotato\.cna/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2108 = /SweetPotato\.csproj/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2109 = /SweetPotato\.exe/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2110 = /SweetPotato\.ImpersonationToken/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2111 = /SweetPotato\.sln/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2112 = /syscall_disable_priv\s/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2113 = /syscall_enable_priv\s/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2114 = /syscalls\.asm/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2115 = /syscalls_dump\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2116 = /syscalls_inject\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2117 = /syscalls_inject\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2118 = /syscalls_shinject\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2119 = /syscalls_shspawn\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2120 = /syscalls_spawn\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2121 = /syscalls_spawn\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2122 = /syscallsapcspawn\.x64/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2123 = /syscalls\-asm\.h/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2124 = /syscallsdump\.x64/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2125 = /syscallsinject\.x64/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2126 = /syscallsspawn\.x64/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2127 = /SysWhispers\.git\s/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2128 = /syswhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2129 = /syswhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2130 = /SysWhispers2/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2131 = /TailorScan\.exe\s/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2132 = /TailorScan_darwin/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2133 = /TailorScan_freebsd/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2134 = /TailorScan_linux_/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2135 = /TailorScan_netbsd_/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2136 = /TailorScan_openbsd_/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2137 = /TailorScan_windows_.{0,1000}\.exe/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2138 = /TaskShell\.exe\s.{0,1000}\s\-b\s.{0,1000}\.exe/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2139 = /TaskShell\.exe\s.{0,1000}\s\-s\s.{0,1000}SYSTEM/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string2140 = /teamserver.{0,1000}\sno_evasion\.profile/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string2141 = /TeamServer\.prop/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string2142 = /Temp\\dumpert/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string2143 = /test_invoke_bof\.x64\.o/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2144 = /tgtdelegation\s/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2145 = /tgtdelegation\.cna/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2146 = /tgtdelegation\.x64/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2147 = /tgtdelegation\.x86/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2148 = /tgtParse\.py\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2149 = /third_party\/SharpGen/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2150 = /third\-party.{0,1000}winvnc.{0,1000}\.dll/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2151 = /threatexpress.{0,1000}malleable/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string2152 = /threatexpress\/cs2modrewrite/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2153 = /ticketConverter\.py\s.{0,1000}\.ccache\s/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string2154 = /tijme\/kernel\-mii/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2155 = /TikiLoader.{0,1000}Hollower/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2156 = /TikiLoader\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2157 = /TikiLoader\./ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2158 = /TikiLoader\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2159 = /TikiLoader\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2160 = /TikiLoader\.Injector/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2161 = /TikiLoader\\TikiLoader/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2162 = /TikiSpawn\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2163 = /TikiSpawn\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2164 = /TikiSpawn\.ps1/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2165 = /TikiSpawnAs/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2166 = /TikiSpawnAsAdmin/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2167 = /TikiSpawnElevated/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2168 = /TikiSpawnWOppid/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2169 = /TikiSpawnWppid/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2170 = /TikiTorch\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2171 = /TikiVader\./ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2172 = /timwhitez\/Doge\-Loader/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2173 = /Tmprovider\.dll/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2174 = /toggle_privileges\.cna/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2175 = /toggle_privileges_bof\./ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2176 = /Toggle_Token_Privileges_BOF/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2177 = /ToggleWDigest/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string2178 = /TokenStripBOF\/src/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2179 = /token\-vault\ssteal/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2180 = /token\-vault\.cna/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2181 = /token\-vault\.x64\.o/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2182 = /token\-vault\.x86\.o/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string2183 = /trainr3kt\/MemReader_BoF/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string2184 = /trainr3kt\/Readfile_BoF/ nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2185 = /TrustedPath\-UACBypass\-BOF/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2186 = /Tycx2ry\/SweetPotato/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2187 = /Tylous\/SourcePoint/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2188 = /UACBypass\-BOF/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2189 = /uac\-schtasks\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2190 = /uac\-schtasks/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string2191 = /uac\-silentcleanup/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2192 = /uac\-token\-duplication/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2193 = /uhttpsharp\./ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2194 = /uknowsec\/TailorScan/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2195 = /UMJjAiNUUtvNww0lBj9tzWegwphuIn6hNP9eeIDfOrcHJ3nozYFPT\-Jl7WsmbmjZnQXUesoJkcJkpdYEdqgQFE6QZgjWVsLSSDonL28DYDVJ/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2196 = /Un1k0d3r\/SCShell/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string2197 = /ursnif_IcedID\.profile/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2198 = /Visual\-Studio\-BOF\-template/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2199 = /vssenum\.x64\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2200 = /vssenum\.x86\./ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string2201 = /vysecurity\/ANGRYPUPPY/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2202 = /wcfrelayserver\.py/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2203 = /wdigest\!g_fParameter_UseLogonCredential/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2204 = /wdigest\!g_IsCredGuardEnabled/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2205 = /whereami\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2206 = /whereami\.x64/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2207 = /WhoamiGetTokenInfo/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2208 = /wifidump\.cna/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string2209 = /windows\-exploit\-suggester\./ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2210 = /winrmdll\s/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2211 = /winrmdll\./ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2212 = /Winsocky\-main/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string2213 = /WKL\-Sec\/HiddenDesktop/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2214 = /WKL\-Sec\/Winsocky/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2215 = /wkssvc_\#\#/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string2216 = /Wmi_Persistence\.ps1/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2217 = /wmi\-event\-lateral\-movement\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2218 = /WMI\-EventSub\.cpp/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2219 = /wmi\-lateral\-movement\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2220 = /WMI\-ProcessCreate\.cpp/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string2221 = /write_cs_teamserver/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2222 = /WriteAndExecuteShellcode/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string2223 = /WritePayloadDllTransacted/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2224 = /wscript_elevator/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string2225 = /wts_enum_remote_processes/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string2226 = /wumb0\/rust_bof/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string2227 = /xforcered\/CredBandit/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/xforcered/Detect-Hooks
        $string2228 = /xforcered\/Detect\-Hooks/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2229 = /xor\.exe\s.{0,1000}\.txt/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string2230 = /xor_payload/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2231 = /xpipe\s\\\\/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2232 = /xpipe.{0,1000}lsass/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2233 = /xpipe\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2234 = /xpipe\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2235 = /xpipe\.o/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string2236 = /YDHCUI\/csload\.net/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string2237 = /YDHCUI\/manjusaka/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string2238 = /youcantpatchthis/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2239 = /ysoserial\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2240 = /YwBhAGwAYwA\=/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2241 = /zerologon\.x64/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2242 = /zerologon\.x86/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2243 = /ZeroLogon\-BOF/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2244 = /zha0gongz1/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2245 = /zha0gongz1\/DesertFox/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2246 = /ziiiiizzzb/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2247 = /ziiiiizzzib/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2248 = /\\\\demoagent_11/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2249 = /\\\\demoagent_22/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2250 = /\\\\DserNamePipe/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2251 = /\\\\f4c3/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2252 = /\\\\f53f/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2253 = /\\\\fullduplex_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2254 = /\\\\interprocess_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2255 = /\\\\lsarpc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2256 = /\\\\mojo_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2257 = /\\\\msagent_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2258 = /\\\\MsFteWds/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2259 = /\\\\msrpc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2260 = /\\\\MSSE\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2261 = /\\\\mypipe\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2262 = /\\\\netlogon_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2263 = /\\\\ntsvcs/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2264 = /\\\\PGMessagePipe/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2265 = /\\\\postex_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2266 = /\\\\postex_ssh_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2267 = /\\\\samr_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2268 = /\\\\scerpc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2269 = /\\\\SearchTextHarvester/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2270 = /\\\\spoolss_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2271 = /\\\\srvsvc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2272 = /\\\\status_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2273 = /\\\\UIA_PIPE/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2274 = /\\\\win\\msrpc_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2275 = /\\\\winsock/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2276 = /\\\\Winsock2\\CatalogChangeListener\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2277 = /\\\\wkssvc_/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string2278 = /detect\-hooks/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2279 = /doc\.1a\..{0,1000}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2280 = /doc\.4a\..{0,1000}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2281 = /doc\.bc\..{0,1000}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2282 = /doc\.md\..{0,1000}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2283 = /doc\.po\..{0,1000}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2284 = /doc\.tx\..{0,1000}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2285 = /doc\-stg\-prepend.{0,1000}\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2286 = /doc\-stg\-sh.{0,1000}\./ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2287 = /dumpwifi\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2288 = /etw\sstop/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2289 = /EVUAC\s/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2290 = /fw_walk\sdisplay/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2291 = /fw_walk\sstatus/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2292 = /fw_walk\stotal/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2293 = /get\-delegation\s/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2294 = /get\-spns\s/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string2295 = /koh\sexit/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string2296 = /koh\slist/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2297 = /Ladon\s.{0,1000}\-.{0,1000}\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2298 = /Ladon\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2299 = /Ladon\s.{0,1000}\/.{0,1000}\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2300 = /Ladon\sMac\s.{0,1000}\s/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string2301 = /LdapSignCheck\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2302 = /load\s.{0,1000}\.cna/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string2303 = /make_token\s/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string2304 = /needle_sift\s/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string2305 = /remotereg\s/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2306 = /rev2self/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string2307 = /scrun\.exe\s/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string2308 = /shell\.exe\s\-u\shttp:\/\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2309 = /SigFlip\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string2310 = /sleeper\sforce/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string2311 = /sleeper\soff/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string2312 = /sleeper\son/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string2313 = /spawn\s.{0,1000}\.exe\s.{0,1000}\.bin/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string2314 = /TokenStrip\s/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2315 = /token\-vault\screate/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2316 = /token\-vault\sremove/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2317 = /token\-vault\sset\s/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2318 = /token\-vault\sshow/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2319 = /token\-vault\suse/ nocase ascii wide

    condition:
        any of them
}
