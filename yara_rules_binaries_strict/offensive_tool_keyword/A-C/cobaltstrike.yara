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
        $string140 = /\.\/c2lint\s/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string141 = /\.\/Dent\s\-/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string142 = /\.\/manjusaka/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string143 = /\.\/ScareCrow\s/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string144 = /\.\/SourcePoint\s/ nocase ascii wide
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
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string217 = "/AggressorScripts" nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string218 = "/AggressorScripts" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string219 = "/AggressorScripts" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string220 = "/agscript " nocase ascii wide
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
        $string250 = "/bin/AceLdr" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string251 = /\/bin\/Sleeper\.o/ nocase ascii wide
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
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string306 = /\/CoffeeLdr\.c/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string307 = "/CoffeeLdr/" nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string308 = "/COFFLoader" nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string309 = "/COFFLoader2/" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string310 = "/com/blackh4t/" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string311 = /\/comfoo\.profile/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string312 = /\/CookieProcessor\.cs/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string313 = /\/core\/browser_darwin\.go/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string314 = /\/core\/browser_linux\.go/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string315 = /\/core\/browser_windows\.go/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string316 = "/Cracked5pider/" nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string317 = "/credBandit/" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string318 = /\/CredEnum\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string319 = /\/CredEnum\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string320 = /\/CredEnum\.h/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string321 = /\/CredPrompt\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string322 = /\/CredPrompt\/credprompt\.c/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string323 = /\/CrossC2\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string324 = "/CrossC2/" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string325 = "/CrossC2Kit" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string326 = "/CrossC2Kit/" nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string327 = "/CrossNet-Beta/" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string328 = "/crypt0p3g/" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string329 = "/cs2modrewrite/" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string330 = "/CS-BOFs/" nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string331 = "/CSharpWinRM" nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string332 = "/C--Shellcode" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string333 = /\/CS\-Loader\.go/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string334 = "/CS-Loader/" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string335 = "/csOnvps/" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string336 = "/csOnvps/" nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string337 = "/cs-rdll-ipc-example/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string338 = "/CS-Remote-OPs-BOF" nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string339 = "/cs-token-vault/" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string340 = /\/curl\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string341 = /\/curl\.x64\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string342 = /\/curl\.x86\.o/ nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string343 = "/custom_payload_generator/" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string344 = "/CWoNaJLBo/VTNeWw11212/" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string345 = "/CWoNaJLBo/VTNeWw11213/" nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string346 = "/DCOM Lateral Movement/" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string347 = /\/defender\-exclusions\/.{0,100}defender/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string348 = /\/defender\-exclusions\/.{0,100}exclusion/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string349 = "/DelegationBOF/" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string350 = /\/demo_bof\.c/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string351 = /\/Dent\/.{0,100}\/Loader\/Loader\.go/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string352 = /\/Dent\/Dent\.go/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string353 = "/Dent/Loader" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string354 = /\/DesertFox\/archive\/.{0,100}\.zip/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string355 = /\/detect\-hooks\.c/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string356 = /\/detect\-hooks\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string357 = /\/detect\-hooks\.h/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string358 = "/Detect-Hooks/" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string359 = /\/dist\/fw_walk\./ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string360 = "/DLL-Hijack" nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string361 = "/Doge-Loader/" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string362 = "/DotNet/SigFlip" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string363 = /\/dukes_apt29\.profile/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string364 = /\/dump_lsass\./ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string365 = /\/dumpert\.c/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string366 = "/Dumpert/" nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string367 = /\/dumpXor\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string368 = "/dumpXor/dumpXor" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string369 = /\/ElevateKit\/elevate\./ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string370 = "/ELFLoader/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string371 = /\/emotet\.profile/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string372 = /\/enableuser\/enableuser\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string373 = /\/enableuser\/enableuser\.x86\./ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string374 = /\/EnumCLR\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string375 = /\/enumerate\.cna/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string376 = /\/Erebus\/.{0,100}\.dll/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string377 = /\/Erebus\/.{0,100}\.exe/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string378 = /\/Erebus\-email\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string379 = /\/etumbot\.profile/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string380 = /\/etw\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string381 = /\/etw\.x64\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string382 = /\/etw\.x86\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string383 = "/EventViewerUAC/" nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string384 = "/EventViewerUAC/" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string385 = /\/evil\.cpp/ nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string386 = /\/exports_function_hid\.txt/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string387 = /\/fiesta\.profile/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string388 = /\/fiesta2\.profile/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string389 = /\/final_shellcode_size\.txt/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string390 = /\/FindModule\.c/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string391 = /\/FindObjects\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string392 = "/Fodetect-hooksx64" nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string393 = "/FuckThatPacker" nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string394 = "/G0ldenGunSec/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string395 = /\/gandcrab\.profile/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string396 = /\/geacon\.git/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string397 = /\/geacon\/.{0,100}beacon/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string398 = "/geacon_pro" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string399 = /\/get\-loggedon\/.{0,100}\.c/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string400 = /\/get\-system\/getsystem\.c/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string401 = "/GetWebDAVStatus_BOF/" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string402 = /\/globeimposter\.profile/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string403 = "/guervild/BOFs" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string404 = /\/hancitor\.profile/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com/EspressoCake/HandleKatz_BOF
        $string405 = "/HandleKatz_BOF" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string406 = /\/HaryyUser\.exe/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string407 = /\/havex\.profile/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string408 = /\/HiddenDesktop\.git/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string409 = /\/hollow\.x64\./ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string410 = /\/hooks\/spoof\.c/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string411 = /\/hostenum\.py/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string412 = /\/HouQing\/.{0,100}\/Loader\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string413 = "/injectAmsiBypass/" nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string414 = "/inject-assembly/" nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string415 = /\/injectEtw\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string416 = "/Injection/clipboard/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string417 = "/Injection/conhost/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string418 = "/Injection/createremotethread/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string419 = "/Injection/ctray/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string420 = "/Injection/dde/" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string421 = /\/Injection\/Injection\.cna/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string422 = "/Injection/kernelcallbacktable" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string423 = "/Injection/ntcreatethread" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string424 = "/Injection/ntcreatethread/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string425 = "/Injection/ntqueueapcthread" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string426 = "/Injection/setthreadcontext" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string427 = "/Injection/svcctrl/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string428 = "/Injection/tooltip/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string429 = "/Injection/uxsubclassinfo" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string430 = "/InlineWhispers" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string431 = /\/Internals\/Coff\.cs/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string432 = /\/Inveigh\.txt/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string433 = "/Invoke-Bof/" nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string434 = /\/Invoke\-HostEnum\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string435 = /\/jaff\.profile/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string436 = /\/jasperloader\.profile/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string437 = /\/K8_CS_.{0,100}_.{0,100}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string438 = "/k8gege/" nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string439 = "/k8gege/scrun/" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string440 = "/k8gege520" nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string441 = /\/kdstab\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string442 = /\/KDStab\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string443 = "/KDStab/" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string444 = /\/Kerbeus\-BOF\.git/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string445 = "/Kerbeus-BOF/" nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string446 = /\/KernelMii\.c/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string447 = /\/Koh\/.{0,100}\.cs/ nocase ascii wide
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
        $string459 = /\/logs\/.{0,100}\/becon_.{0,100}\.log/ nocase ascii wide
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
        $string554 = "/ScareCrow -I " nocase ascii wide
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
        $string564 = "/ServerScanForLinux/" nocase ascii wide
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
        $string607 = /\/teamserver\.service/ nocase ascii wide
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
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string624 = "/UAC-SilentClean/" nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/Cobalt-Strike/unhook-bof
        $string625 = "/unhook-bof" nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string626 = "/unhook-bof" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string627 = "/UTWOqVQ132/" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string628 = "/vssenum/" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string629 = /\/WdToggle\.c/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string630 = /\/WdToggle\.h/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string631 = /\/webshell\/.{0,100}\.aspx/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string632 = /\/webshell\/.{0,100}\.jsp/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string633 = /\/webshell\/.{0,100}\.php/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string634 = /\/wifidump\.c/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string635 = /\/WindowsVault\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string636 = /\/WindowsVault\.h/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string637 = /\/winrm\.cpp/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string638 = "/winrmdll" nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string639 = "/winrm-reflective-dll/" nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string640 = /\/Winsocky\.git/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string641 = "/WMI Lateral Movement/" nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string642 = "/wwlib/lolbins/" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string643 = /\/xen\-mimi\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string644 = /\/xor\/stager\.txt/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string645 = /\/xor\/xor\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string646 = "/xPipe/" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string647 = "/yanghaoi/_CNA" nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string648 = /\/zerologon\.cna/ nocase ascii wide
        // Description: cobaltstrike default content strings
        // Reference: https://www.cobaltstrike.com/
        $string649 = /\[\+\]\sPrivileged\sfile\scopy\ssuccess\!\s/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string650 = /\[\'spawnto\'\]/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string651 = /\\\\\.\\pipe\\bypassuac/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string652 = /\\\\\.\\pipe\\hashdump/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string653 = /\\\\\.\\pipe\\keylogger/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string654 = /\\\\\.\\pipe\\mimikatz/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string655 = /\\\\\.\\pipe\\netview/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string656 = /\\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string657 = /\\\\\.\\pipe\\portscan/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string658 = /\\\\\.\\pipe\\screenshot/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string659 = /\\\\\.\\pipe\\sshagent/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string660 = /\\\\\\\\\.\\\\pipe\\\\bypassuac/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string661 = /\\\\\\\\\.\\\\pipe\\\\hashdump/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string662 = /\\\\\\\\\.\\\\pipe\\\\keylogger/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string663 = /\\\\\\\\\.\\\\pipe\\\\mimikatz/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string664 = /\\\\\\\\\.\\\\pipe\\\\netview/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string665 = /\\\\\\\\\.\\\\pipe\\\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string666 = /\\\\\\\\\.\\\\pipe\\\\portscan/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string667 = /\\\\\\\\\.\\\\pipe\\\\screenshot/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string668 = /\\\\\\\\\.\\\\pipe\\\\sshagent/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string669 = /\\\\GetWebDAVStatus\.exe/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string670 = /\\\\pipe\\\\DAV\sRPC\sSERVICE/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string671 = /\\8e8988b257e9dd2ea44ff03d44d26467b7c9ec16/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string672 = /\\asreproasting\.c/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string673 = /\\beacon\.exe/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string674 = /\\CrossC2\./ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string675 = /\\CROSSNET\\CROSSNET\\/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string676 = /\\dumpert\./ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string677 = /\\Dumpert\\/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string678 = /\\DumpShellcode/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string679 = /\\dumpXor\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string680 = /\\dumpXor\\x64\\/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string681 = /\\ELF\\portscan/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string682 = /\\ELF\\serverscan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string683 = /\\evil\.dll/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string684 = /\\geacon\\tools\\BeaconTool\\/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string685 = /\\GetWebDAVStatus\\/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string686 = /\\GetWebDAVStatus_x64/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string687 = /\\HackBrowserData/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string688 = /\\HiddenDesktop\\/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string689 = /\\HostEnum\.ps1/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string690 = /\\kdstab\.exe/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string691 = /\\kerberoasting\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string692 = /\\Kerbeus\-BOF\\/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string693 = /\\Koh\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string694 = /\\Koh\.pdb/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string695 = /\\Koh\\Koh\./ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string696 = /\\Ladon\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string697 = /\\Ladon\.ps1/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string698 = /\\LogonScreen\.exe/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string699 = /\\lsass\.dmp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string700 = /\\Mockingjay_BOF\./ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string701 = /\\No\-Consolation\\source\\/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string702 = /\\portbender\./ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string703 = /\\PowerView\.cna/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string704 = /\\PowerView\.exe/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string705 = /\\PowerView\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string706 = /\\PowerView3\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string707 = /\\RunBOF\.exe/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string708 = /\\RunOF\.exe/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string709 = /\\RunOF\\bin\\/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string710 = /\\samantha\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string711 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string712 = /\\SigFlip\.exe/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string713 = /\\SilentClean\.exe/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string714 = /\\StayKit\.cna/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string715 = /\\systemic\.txt/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string716 = /\\TASKSHELL\.EXE/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string717 = /\\TikiCompiler\.txt/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string718 = /\\TikiService\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string719 = /\\TikiSpawn\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string720 = /\\tikispawn\.xml/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string721 = /\\TikiTorch\\Aggressor/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string722 = /\\xpipe\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string723 = /\\xpipe\.o/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string724 = /\]\scompile\sgeacon\swith\sthe\spublic\skey\sfrom\s\.beacon_keys/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string725 = /\]\suse\sthe\saes\skey\sfrom\sthe\sbeacon\'s\sonline\sinfo\sto\sencrypt\stransfer\sdata\s\(base64\sformat/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string726 = /\]\suse\sthe\spublic\skey\sfrom\s\.beacon_keys\sto\sdecrypt\sthe\sbeacon\'s\sonline\sinfo/ nocase ascii wide
        // Description: cobaltstrike default content strings
        // Reference: https://www.cobaltstrike.com/
        $string727 = /\]\sWrote\shijack\sDLL\sto\s/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string728 = "_cobaltstrike" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string729 = "_find_sharpgen_dll" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string730 = "_pycobalt_" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string731 = /_tcp_cc2\(/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string732 = /_udp_cc2\(/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string733 = /\<CoffeLdr\.h\>/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string734 = "0xEr3bus/PoolPartyBof" nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string735 = "0xthirteen/MoveKit" nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string736 = "0xthirteen/StayKit" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string737 = "4d5350c8-7f8c-47cf-8cde-c752018af17e" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string738 = "516280565958" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string739 = "516280565959" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string740 = "5a40f11a99d0db4a0b06ab5b95c7da4b1c05b55a99c7c443021bff02c2cf93145c53ff5b" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string741 = "5e98194a01c6b48fa582a6a9fcbb92d6" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string742 = "6e7645c4-32c5-4fe3-aabf-e94c2f4370e7" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string743 = "713724C3-2367-49FA-B03F-AB4B336FB405" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string744 = "732211ae-4891-40d3-b2b6-85ebd6f5ffff" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string745 = "76318bcd19b5f3efe0e51c77593bccd6804c6a30b95c4c51ec528c30c7faca83" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string746 = /7CFC52\.dll/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string747 = /7CFC52CD3F\.dll/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string748 = "913d774e5cf0bfad4adfa900997f7a1a" nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string749 = /AceLdr\..{0,100}\.bin/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string750 = /AceLdr\.zip/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string751 = /adcs_enum\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string752 = /adcs_enum_com\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string753 = /adcs_enum_com2\./ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string754 = /AddUser\-Bof\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string755 = /AddUser\-Bof\.git/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string756 = /AddUser\-Bof\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string757 = /AddUser\-Bof\.x64/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string758 = /AddUser\-Bof\.x86/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string759 = /AddUserToDomainGroup\s.{0,100}Domain\sAdmins/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string760 = /AddUserToDomainGroup\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string761 = /AddUserToDomainGroup\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string762 = "Adminisme/ServerScan/" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string763 = "ag_load_script" nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string764 = /AggressiveProxy\.cna/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string765 = /aggressor\.beacons/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string766 = /aggressor\.bshell/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string767 = /aggressor\.cna/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string768 = /aggressor\.dialog/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string769 = /aggressor\.println/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string770 = /aggressor\.py/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string771 = "Aggressor/TikiTorch" nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string772 = "aggressor-scripts" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string773 = "ajpc500/BOFs" nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string774 = "Allocated shellcode memory in the target process: " nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string775 = "Alphabug_CS" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string776 = "Alphabug_CS" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string777 = "AlphabugX/csOnvps" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string778 = "AlphabugX/csOnvps" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string779 = /Already\sSYSTEM.{0,100}not\selevating/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string780 = /ANGRYPUPPY2\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string781 = "anthemtotheego/Detect-Hooks" nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string782 = "apokryptein/secinject" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string783 = "applocker_enum" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string784 = "applocker-enumerator" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string785 = /apt1_virtuallythere\.profile/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string786 = /arsenal_kit\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string787 = /artifact\.cna/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string788 = /artifact\.cna/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string789 = /artifact\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string790 = /artifact\.x64\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string791 = /artifact\.x86\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string792 = /artifact\.x86\.exe/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string793 = "artifact_payload" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string794 = "artifact_stageless" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string795 = "artifact_stager" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string796 = /artifact32.{0,100}\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string797 = /artifact32\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string798 = /artifact32\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string799 = /artifact32big\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string800 = /artifact32big\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string801 = /artifact32svc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string802 = /artifact32svcbig\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string803 = /artifact64.{0,100}\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string804 = /artifact64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string805 = /artifact64\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string806 = /artifact64\.x64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string807 = /artifact64big\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string808 = /artifact64big\.x64\.dll/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string809 = /artifact64svc\.exe/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string810 = /artifact64svcbig\.exe/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string811 = /artifactbig64\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string812 = /artifactuac.{0,100}\.dll/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string813 = /asktgs\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string814 = /ASRenum\-BOF\./ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string815 = /asreproasting\.x64/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string816 = /Assemblies\/SharpMove\.exe/ nocase ascii wide
        // Description: Cobalt Strike BOFs
        // Reference: https://github.com/AttackTeamFamily/cobaltstrike-bof-toolset
        $string817 = /AttackTeamFamily.{0,100}\-bof\-toolset/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string818 = "ausecwa/bof-registry" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string819 = /auth\/cc2_ssh\./ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string820 = "Backdoor LNK" nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string821 = "--backdoor-all" nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string822 = "backdoorlnkdialog" nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string823 = /backstab\.x64\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string824 = /backstab\.x86\./ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string825 = /BackupPrivSAM\s\\\\/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string826 = /backupprivsam\./ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string827 = /BadPotato\.exe/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string828 = "bawait_upload" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string829 = "bawait_upload_raw" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string830 = "bblockdlls" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string831 = "bbrowserpivot" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string832 = "bbrowserpivot" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string833 = "bbypassuac" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string834 = "bcc2_setenv" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string835 = "bcc2_spawn" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string836 = "bcrossc2_load_dyn" nocase ascii wide
        // Description: Malleable C2 Profiles. A collection of profiles used in different projects using Cobalt Strike & Empire.
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string837 = /BC\-SECURITY.{0,100}Malleable/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string838 = "bdcsync" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string839 = "bdllinject" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string840 = "bdllinject" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string841 = "bdllload" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string842 = "bdllload" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string843 = "bdllspawn" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string844 = "bdllspawn" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string845 = "be041565c155ce5a9129e2d79a2c8d18acf4143a7f3aa2237c15a15a89b6625e" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string846 = "Beacon Payload Generator" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string847 = /beacon\..{0,100}winsrv\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string848 = /beacon\.CommandBuilder/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string849 = /beacon\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string850 = /beacon\.exe/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string851 = /beacon\.exe/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string852 = /beacon\.nim/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string853 = /Beacon\.Object\.File\.zip/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string854 = /beacon\.x64.{0,100}\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string855 = /beacon\.x64.{0,100}\.exe/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string856 = /beacon\.x64\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string857 = /beacon\.x86.{0,100}\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string858 = /beacon\.x86.{0,100}\.exe/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string859 = /beacon_api\.h/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string860 = "beacon_bottom " nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string861 = "Beacon_Com_Struct" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string862 = "beacon_command_describe" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string863 = "beacon_command_detail" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string864 = "beacon_command_register" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string865 = "beacon_commands" nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string866 = /beacon_compatibility\.c/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string867 = /beacon_compatibility\.h/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string868 = "beacon_elevator_describe" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string869 = "beacon_elevator_register" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string870 = "beacon_elevators" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string871 = "beacon_elevators" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string872 = "beacon_execute_job" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string873 = "beacon_exploit_describe" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string874 = "beacon_exploit_register" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string875 = /beacon_funcs\.c/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string876 = /beacon_funcs\.h/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string877 = /beacon_funcs\.x64\./ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string878 = /beacon_funcs\.x86\./ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string879 = /beacon_generate\.py/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string880 = "Beacon_GETPOST" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string881 = "beacon_host_script" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string882 = "beacon_host_script" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string883 = "beacon_inline_execute" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string884 = "beacon_keys -compile geacon_sourcecode_folder" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string885 = "beacon_log_clean" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string886 = /beacon_output_ps\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string887 = "beacon_print" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string888 = "BEACON_RDLL_" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string889 = "beacon_remote_exec_" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string890 = "beacon_remote_exec_method_describe" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string891 = "beacon_remote_exec_method_register" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string892 = "beacon_remote_exec_methods" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string893 = "beacon_remote_exploit" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string894 = "beacon_remote_exploit_arch" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string895 = "beacon_remote_exploit_describe" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string896 = "beacon_remote_exploit_register" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string897 = "beacon_remote_exploits" nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string898 = /beacon_smb\.exe/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string899 = "Beacon_Stage_p2_Stuct" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string900 = "beacon_stage_pipe" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string901 = "Beacon_Stage_Struct_p1" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string902 = "Beacon_Stage_Struct_p3" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string903 = "beacon_stage_tcp" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string904 = "beacon_stage_tcp" nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string905 = /beacon_test\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string906 = "beacon_top " nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string907 = "beacon_top_callback" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string908 = /BeaconApi\.cs/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string909 = "beacon-c2-go" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string910 = "BeaconCleanupProcess" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string911 = /BeaconConsoleWriter\.cs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string912 = "BeaconGetSpawnTo" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string913 = "BeaconGetSpawnTo" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string914 = "BeaconGetSpawnTo" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string915 = /beacongrapher\.py/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string916 = "BeaconInjectProcess" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string917 = "BeaconInjectProcess" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string918 = "BeaconInjectTemporaryProcess" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string919 = "BeaconInjectTemporaryProcess" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string920 = /BeaconJob\.cs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string921 = /BeaconJobWriter\.cs/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string922 = /beaconlogs\.json/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string923 = /beaconlogtracker\.py/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string924 = /BeaconNote\.cna/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string925 = /BeaconNotify\.cna/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string926 = /BeaconObject\.cs/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string927 = "BeaconOutputStreamW" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string928 = /BeaconOutputWriter\.cs/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string929 = /BeaconPrintf\(/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string930 = "BeaconPrintf" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string931 = "BeaconPrintToStreamW" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string932 = "BeaconSpawnTemporaryProcess" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string933 = "BeaconSpawnTemporaryProcess" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string934 = "BeaconTool -" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string935 = /BeaconTool\s\-i\sonline_info\.txt\s\-aes\sdecrypt/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string936 = /BeaconTool\/lib\/sleep\.jar/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string937 = "BeaconUseToken" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string938 = "bgetprivs" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string939 = "bhashdump" nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string940 = /bin\/bof_c\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string941 = /bin\/bof_nim\.o/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string942 = "bkerberos_ccache_use" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string943 = "bkerberos_ticket_purge" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string944 = "bkerberos_ticket_use" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string945 = "bkeylogger" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string946 = "blockdlls start" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string947 = "blockdlls stop" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string948 = "bloginuser" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string949 = "blogonpasswords" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string950 = "BOF prototype works!" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string951 = /bof.{0,100}\/CredEnum\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string952 = /BOF\/.{0,100}procdump\// nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string953 = "bof_allocator" nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string954 = /bof_helper\.py/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string955 = /bof_net_user\.c/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string956 = /bof_net_user\.o/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string957 = "bof_reuse_memory" nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string958 = "BOF2shellcode" nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string959 = /bof2shellcode\.py/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string960 = "BOF-DLL-Inject" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string961 = "bofentry::bof_entry" nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string962 = "BOF-ForeignLsass" nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string963 = /BOF\-IShellWindows\-DCOM\./ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string964 = "BofLdapSignCheck" nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string965 = /bofloader\.bin/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string966 = /bofnet.{0,100}SeriousSam\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string967 = /BOFNET\.Bofs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string968 = /bofnet\.cna/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string969 = /BOFNET\.csproj/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string970 = /BOFNET\.sln/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string971 = /bofnet_boo\s.{0,100}\.boo/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string972 = "bofnet_execute " nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string973 = /bofnet_execute\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string974 = "bofnet_init" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string975 = "bofnet_job " nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string976 = "bofnet_jobkill" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string977 = "bofnet_jobs" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string978 = "bofnet_jobstatus " nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string979 = "bofnet_list" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string980 = "bofnet_listassembiles" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string981 = /bofnet_load\s.{0,100}\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string982 = "bofnet_shutdown" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string983 = "BOFNET_Tests" nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string984 = "bofportscan " nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string985 = /bof\-quser\s.{0,100}\./ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string986 = /bof\-quser\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string987 = "bof-rdphijack" nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string988 = "bof-regsave " nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string989 = "BofRunnerOutput" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string990 = /BOFs.{0,100}\/SyscallsSpawn\// nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string991 = "Bofs/AssemblyLoader" nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string992 = "bof-servicemove " nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string993 = "bof-trustedpath-uacbypass" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string994 = "boku_pe_customMZ" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string995 = "boku_pe_customPE" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string996 = "boku_pe_dll" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string997 = "boku_pe_mask_" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string998 = "boku_pe_MZ_from_C2Profile" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string999 = "boku_strrep" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1000 = "boku7/BokuLoader" nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string1001 = "boku7/HOLLOW" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1002 = /BokuLoader\.cna/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1003 = /BokuLoader\.exe/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1004 = /BokuLoader\.x64/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1005 = /BooExecutorImpl\.cs/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1006 = "bpassthehash" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1007 = "bpowerpick" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1008 = "bpsexec_command" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1009 = "bpsexec_command" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1010 = "bpsexec_psh" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1011 = "bpsinject" nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1012 = /breg\sadd\s.{0,100}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1013 = /breg\sdelete\s.{0,100}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1014 = /breg\squery\s.{0,100}HK/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1015 = "breg_add_string_value" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1016 = "bremote_exec" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1017 = "browser_##" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1018 = "browserpivot " nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1019 = "brun_script_in_mem" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1020 = "brunasadmin" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1021 = "bshinject" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1022 = "bshinject" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1023 = "bshspawn" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1024 = "bsteal_token" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1025 = "bsteal_token" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1026 = /build\sSourcePoint\.go/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1027 = /build\/breg\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1028 = "build_c_shellcode" nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1029 = /BuildBOFs\.exe/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1030 = /BuildBOFs\.sln/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1031 = /bupload_raw.{0,100}\.dll/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1032 = /burp2malleable\./ nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string1033 = /BypassAV\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1034 = /bypass\-pipe\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string1035 = "byt3bl33d3r/BOF-Nim" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1036 = /\-c\sBOF\.cpp\s\-o\sBOF\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1037 = /\-c\sBOF\.cpp\s\-o\sBOF\.x64\.o/ nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1038 = /C\:\\Temp\\poc\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1039 = /C\:\\Windows\\Temp\\move\.exe/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1040 = /C\:\\Windows\\Temp\\moveme\.exe/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1041 = /C\?\?\/generator\.cpp/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1042 = "c2lint " nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1043 = "C2ListenerPort" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1044 = /\-c2\-randomizer\.py/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1045 = "C2ReverseClint" nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1046 = "C2ReverseProxy" nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1047 = "C2ReverseServer" nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1048 = /C2script\/proxy\./ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1049 = "'c2server'" nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1050 = /CACTUSTORCH\.cna/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1051 = /CACTUSTORCH\.cs/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1052 = /CACTUSTORCH\.hta/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1053 = /CACTUSTORCH\.js/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1054 = /CACTUSTORCH\.vba/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1055 = /CACTUSTORCH\.vbe/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1056 = /CACTUSTORCH\.vbs/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1057 = "CALLBACK_HASHDUMP" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1058 = "CALLBACK_KEYSTROKES" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1059 = "CALLBACK_NETVIEW" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1060 = "CALLBACK_PORTSCAN" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1061 = "CALLBACK_TOKEN_STOLEN" nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1062 = /CallBackDump.{0,100}dumpXor/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1063 = /CallbackDump\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1064 = /careCrow.{0,100}_linux_amd64/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1065 = /cat\s.{0,100}\.bin\s\|\sbase64\s\-w\s0\s\>\s.{0,100}\.txt/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1066 = "cc2_keystrokes_" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1067 = /cc2_mimipenguin\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1068 = "cc2_portscan_" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1069 = /cc2_rebind_.{0,100}_get_recv/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1070 = /cc2_rebind_.{0,100}_get_send/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1071 = /cc2_rebind_.{0,100}_post_recv/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1072 = /cc2_rebind_.{0,100}_post_send/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1073 = "cc2_udp_server" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1074 = /cc2FilesColor\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1075 = /cc2ProcessColor\./ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1076 = /CCob\/BOF\.NET/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1077 = /cd\s\.\/whereami\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1078 = /ChatLadon\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1079 = /ChatLadon\.rar/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1080 = "check_and_write_IAT_Hook" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1081 = /check_function\sntdll\.dll\sEtwEventWrite/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1082 = "checkIfHiddenAPICall" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1083 = /chromeKey\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1084 = /chromeKey\.x86/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1085 = "chromiumkeydump" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1086 = "cHux014r17SG3v4gPUrZ0BZjDabMTY2eWDj1tuYdREBg" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1087 = /clipboardinject\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1088 = /clipboardinject\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1089 = /clipboardinject\.x86/ nocase ascii wide
        // Description: CLIPBRDWNDCLASS process injection technique(BOF) - execute beacon shellcode in callback
        // Reference: https://github.com/BronzeTicket/ClipboardWindow-Inject
        $string1090 = "ClipboardWindow-Inject" nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1091 = /clipmon\.sln/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1092 = "Cobalt Strike" nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1093 = /cobaltclip\.cna/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1094 = /cobaltclip\.exe/ nocase ascii wide
        // Description: cobaltstrike binary for windows - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network. While penetration tests focus on unpatched vulnerabilities and misconfigurations. these assessments benefit security operations and incident response.
        // Reference: https://www.cobaltstrike.com/
        $string1095 = "cobaltstrike" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1096 = "cobalt-strike" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1097 = /cobaltstrike\.store/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1098 = "Cobalt-Strike/bof_template" nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1099 = /CodeLoad\(shellcode\)/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1100 = /coff_definitions\.h/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1101 = /COFF_Loader\./ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1102 = "COFF_PREP_BEACON" nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1103 = /CoffeeLdr.{0,100}\sgo\s/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1104 = /CoffeeLdr\.x64\.exe/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1105 = /CoffeeLdr\.x86\.exe/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1106 = "COFFELDR_COFFELDR_H" nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1107 = /COFFLoader\./ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1108 = /COFFLoader64\.exe/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1109 = /com_exec_go\(/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1110 = /com\-exec\.cna/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1111 = /common\.ReflectiveDLL/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1112 = "comnap_##" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1113 = "comnode_##" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1114 = "connormcgarr/tgtdelegation" nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1115 = /cookie_graber_x64\.o/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1116 = /cookie\-graber\.c/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1117 = /cookie\-graber_x64\.exe/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1118 = "Cookie-Graber-BOF" nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1119 = /CookieProcessor\.exe/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1120 = /covid19_koadic\.profile/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1121 = "crawlLdrDllList" nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1122 = /credBandit\s.{0,100}\soutput/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1123 = /credBandit\./ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1124 = "credBanditx64" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string1125 = /CredPrompt\/CredPrompt\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1126 = "cribdragg3r/Alaris" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1127 = /crimeware.{0,100}\/zeus\.profile/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1128 = "crisprss/PrintSpoofer" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1129 = /cross_s4u\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1130 = /cross_s4u\.x64\.o/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1131 = "CrossC2 beacon" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1132 = /CrossC2\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1133 = "crossc2_entry" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1134 = /crossc2_portscan\./ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1135 = /crossc2_serverscan\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1136 = "CrossC2Beacon" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1137 = /CrossC2Kit\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1138 = /CrossC2Kit\./ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1139 = /CrossC2Kit\.git/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1140 = "CrossC2Kit_demo" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1141 = "crossc2kit_latest" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1142 = "CrossC2Kit_Loader" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1143 = "CrossC2Listener" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1144 = "CrossC2MemScriptEng" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1145 = "CrossC2Script" nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1146 = /CrossNet\.exe/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1147 = "CRTInjectAsSystem" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1148 = "CRTInjectElevated" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1149 = "CRTInjectWithoutPid" nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1150 = /cs2modrewrite\.py/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1151 = /cs2nginx\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1152 = "CS-Avoid-killing" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1153 = "CS-BOFs/lsass" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1154 = "CSharpNamedPipeLoader" nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1155 = /csload\.net\/.{0,100}\/muma\./ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1156 = /csOnvps.{0,100}teamserver/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1157 = "CS-Remote-OPs-BOF" nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string1158 = /CSSG_load\.cna/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1159 = /cs\-token\-vault\.git/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1160 = "cube0x0/LdapSignCheck" nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string1161 = /custom_payload_generator\./ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1162 = "CustomKeyboardLayoutPersistence" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1163 = /CVE_20.{0,100}\.dll/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1164 = /cve\-20\.x64\.dll/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1165 = /cve\-20\.x86\.dll/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1166 = "DallasFR/Cobalt-Clip" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1167 = "darkr4y/geacon" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1168 = /dcsync\@protonmail\.com/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1169 = /dcsyncattack\(/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1170 = /dcsyncattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1171 = /dcsyncclient\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1172 = /dcsyncclient\.py/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1173 = "DeEpinGh0st/Erebus" nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1174 = "DefaultBeaconApi" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1175 = /demo\-bof\.cna/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string1176 = /detect\-hooksx64\./ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1177 = "DisableAllWindowsSoftwareFirewalls" nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1178 = /disableeventvwr\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1179 = /dll\\reflective_dll\./ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1180 = "dll_hijack_hunter" nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1181 = "DLL_Imports_BOF" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1182 = "DLL_TO_HIJACK_WIN10" nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1183 = "DLL-Hijack-Search-Order-BOF" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1184 = "dllinject " nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1185 = "dns_beacon_beacon" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1186 = "dns_beacon_dns_idle" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1187 = "dns_beacon_dns_sleep" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1188 = "dns_beacon_dns_stager_prepend" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1189 = "dns_beacon_dns_stager_subhost" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1190 = "dns_beacon_dns_ttl" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1191 = "dns_beacon_get_A" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1192 = "dns_beacon_get_TXT" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1193 = "dns_beacon_maxdns" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1194 = "dns_beacon_ns_response" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1195 = "dns_beacon_put_metadata" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1196 = "dns_beacon_put_output" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1197 = /dns_redir\.sh\s/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1198 = "dns_stager_prepend" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1199 = "'dns_stager_prepend'" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1200 = "'dns_stager_subhost'" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1201 = "dns-beacon " nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1202 = /dnspayload\.bin/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1203 = /do_attack\(/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string1204 = /Doge\-Loader.{0,100}xor\.go/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1205 = /douknowwhoami\?d/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1206 = "dr0op/CrossNet" nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1207 = /DReverseProxy\.git/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1208 = /DReverseServer\.go/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1209 = "drop_malleable_unknown_" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1210 = "drop_malleable_with_invalid_" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1211 = "drop_malleable_without_" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1212 = /dropper32\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1213 = /dropper64\.exe/ nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string1214 = "dtmsecurity/bof_helper" nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1215 = /Dumpert\.bin/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1216 = /Dumpert\.exe/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1217 = "Dumpert-Aggressor" nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1218 = /DumpShellcode\.exe/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1219 = /dumpXor\.exe\s/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1220 = /EasyPersistent\.cna/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1221 = "ebdf64076861a73d92416c6203d50dd25f4c991372f7d47e7146e29ab41a6892" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1222 = "elevate juicypotato " nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1223 = "elevate Printspoofer" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1224 = "elevate svc-exe " nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1225 = /ELFLoader\.c/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1226 = /ELFLoader\.h/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1227 = /ELFLoader\.out/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1228 = "empire AttackServers" nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1229 = "EncodeGroup/AggressiveProxy" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1230 = "EncodeGroup/UAC-SilentClean" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1231 = /encrypt\/encryptFile\.go/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1232 = /encrypt\/encryptUrl\.go/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1233 = /EncryptShellcode\(/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1234 = "engjibo/NetUser" nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string1235 = /EnumCLR\.exe/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1236 = /Erebus\/.{0,100}spacerunner/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1237 = "EspressoCake/PPLDump_BOF" nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1238 = /EventAggregation\.dll\.bak/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1239 = /eventspy\.cna/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1240 = /EventSub\-Aggressor\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1241 = /EventViewerUAC\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1242 = /EventViewerUAC\./ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1243 = /EventViewerUAC\.x64/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1244 = /EventViewerUAC\.x86/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1245 = "EventViewerUAC_BOF" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1246 = "eventvwr_elevator" nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1247 = /EVUAC\s.{0,100}\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1248 = "ewby/Mockingjay_BOF" nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1249 = /example\-bof\.sln/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1250 = /execmethod.{0,100}PowerPick/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1251 = /execmethod.{0,100}PowerShell/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1252 = "execute_bof " nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1253 = /execute\-assembly\s.{0,100}\.exe\s/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1254 = "executepersistence" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1255 = "Export-PowerViewCSV" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1256 = "extract_reflective_loader" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1257 = "Fiesta Exploit Kit" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1258 = /FileControler\/FileControler_x64\.dll/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1259 = /FileControler\/FileControler_x86\.dll/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1260 = /find_payload\(/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1261 = "findgpocomputeradmin" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1262 = "Find-GPOComputerAdmin" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1263 = "Find-InterestingDomainAcl" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1264 = "findinterestingdomainsharefile" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1265 = "Find-InterestingDomainShareFile" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1266 = "findlocaladminaccess" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1267 = "findlocaladminaccess" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1268 = "Find-LocalAdminAccess" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1269 = "Find-LocalAdminAccess" nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1270 = /FindModule\s.{0,100}\.dll/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1271 = "FindObjects-BOF" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1272 = "FindProcessTokenAndDuplicate" nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1273 = /FindProcHandle\s.{0,100}lsass/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1274 = "Firewall_Walker_BOF" nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1275 = "fishing_with_hollowing" nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1276 = /foreign_access\.cna/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1277 = /foreign_lsass\s.{0,100}\s/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1278 = /foreign_lsass\.c/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1279 = /foreign_lsass\.x64/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1280 = /foreign_lsass\.x86/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1281 = /\-\-format\-string\sziiiiizzzb\s.{0,100}\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1282 = "--format-string ziiiiizzzib " nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1283 = "fortra/No-Consolation" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1284 = "fucksetuptools" nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string1285 = /FuckThatPacker\./ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1286 = "FunnyWolf/pystinger" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1287 = "fw_walk disable" nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1288 = "G0ldenGunSec/GetWebDAVStatus" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1289 = /GadgetToJScript\.exe\s\-a\s/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1290 = "Gality369/CS-Loader" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1291 = "gather/keylogger" nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1292 = /geacon.{0,100}\/cmd\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1293 = /genCrossC2\./ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1294 = "generate_beacon" nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1295 = /generate\-rotating\-beacon\./ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1296 = "GeorgePatsias/ScareCrow" nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string1297 = "get_BeaconHealthCheck_settings" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1298 = "get_dns_dnsidle" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1299 = "get_dns_sleep" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1300 = /get_password_policy\.x64\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1301 = /get_password_policy\.x86\./ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1302 = "get_post_ex_pipename_list" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1303 = "get_post_ex_spawnto_x" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1304 = "get_process_inject_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1305 = "get_process_inject_bof_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1306 = "get_process_inject_execute" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1307 = "get_stage_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1308 = "get_stage_magic_mz_64" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1309 = "get_stage_magic_mz_86" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1310 = "get_stage_magic_pe" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1311 = "get_virtual_Hook_address" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1312 = "getAggressorClient" nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1313 = "Get-BeaconAPI" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1314 = "Get-CachedRDPConnection" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1315 = "getCrossC2Beacon" nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1316 = "getCrossC2Site" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1317 = "getdomainspnticket" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1318 = "Get-DomainSPNTicket" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1319 = "getexploitablesystem" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1320 = "Get-ExploitableSystem" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1321 = "GetHijackableDllName" nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1322 = "GetNTLMChallengeBase64" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1323 = /GetShellcode\(/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1324 = /GetWebDAVStatus\.csproj/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1325 = /GetWebDAVStatus\.sln/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1326 = "GetWebDAVStatus_DotNet" nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1327 = /GetWebDAVStatus_x64\.o/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1328 = "getwmiregcachedrdpconnection" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1329 = "Get-WMIRegCachedRDPConnection" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1330 = "getwmireglastloggedon" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1331 = "Get-WMIRegLastLoggedOn" nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1332 = /gexplorer\.exe/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1333 = "GhostPack/Koh" nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1334 = /github.{0,100}\/MoveKit\.git/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1335 = /github\.com\/k8gege/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1336 = /github\.com\/rasta\-mouse\// nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1337 = /github\.com\/SpiderLabs\// nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1338 = "gloxec/CrossC2" nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1339 = /go_shellcode_encode\.py/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1340 = /go\-shellcode\.py/ nocase ascii wide
        // Description: generate shellcode
        // Reference: https://github.com/fcre1938/goShellCodeByPassVT
        $string1341 = "goShellCodeByPassVT" nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1342 = /hackbrowersdata\.cna/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1343 = "hack-browser-data/" nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1344 = /handlekatz\.x64\./ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1345 = /handlekatz_bof\./ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1346 = "Hangingsword/HouQing" nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1347 = "hd-launch-cmd " nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1348 = /headers\/exploit\.h/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1349 = /headers\/HandleKatz\.h/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1350 = "Henkru/cs-token-vault" nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1351 = /Hidden\.Desktop\.mp4/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1352 = /HiddenDesktop\s.{0,100}\s/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1353 = /HiddenDesktop\./ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1354 = /HiddenDesktop\.x64\.bin/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1355 = /HiddenDesktop\.x86\.bin/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1356 = /HiddenDesktop\.zip/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1357 = "hijack_hunter " nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1358 = "hijack_remote_thread" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1359 = /HiveJack\-Console\.exe/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string1360 = /hollow\s.{0,100}\.exe\s.{0,100}\.bin/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1361 = /hollower\.Hollow\(/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1362 = /houqingv1\.0\.zip/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1363 = /html\/js\/beacons\.js/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1364 = /http.{0,100}\/zha0gongz1/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1365 = /http.{0,100}\:3200\/manjusaka/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1366 = /http.{0,100}\:801\/bq1iFEP2/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1367 = /http\:\/\/127\.0\.0\.1\:8000\/1\.jpg/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1368 = "http_stager_client_header" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1369 = "http_stager_server_append" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1370 = "http_stager_server_header" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1371 = "http_stager_server_prepend" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1372 = "http_stager_uri_x64" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1373 = "http_stager_uri_x86" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1374 = /http1\.x64\.bin/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1375 = /http1\.x64\.dll/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1376 = /httpattack\.py/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1377 = /httppayload\.bin/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1378 = "http-redwarden" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1379 = /httprelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1380 = /httprelayserver\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1381 = "'http-stager'" nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1382 = /HVNC\sServer\.exe/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1383 = /HVNC\\\sServer/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string1384 = "IcebreakerSecurity/DelegationBOF" nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1385 = "IcebreakerSecurity/PersistBOF" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1386 = /imapattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1387 = /imaprelayclient\.py/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1388 = /impacket\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1389 = "ImpersonateLocalService" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1390 = /import\spe\.OBJExecutable/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1391 = /include\sbeacon\.h/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1392 = /include\sinjection\.c/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1393 = "inject-amsiBypass " nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1394 = /inject\-amsiBypass\./ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1395 = "inject-assembly " nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1396 = /inject\-assembly\.cna/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1397 = /injectassembly\.x64\.bin/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1398 = /injectassembly\.x64\.o/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1399 = "injectEtwBypass" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1400 = "InjectShellcode" nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1401 = "inline-execute " nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1402 = /inline\-execute.{0,100}whereami\.x64/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1403 = "InlineExecute-Assembly" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string1404 = /InlineWhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string1405 = "InlineWhispers2" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1406 = "install impacket" nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1407 = "InvokeBloodHound" nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1408 = "Invoke-Bof " nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1409 = /Invoke\-Bof\.ps1/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1410 = "invokechecklocaladminaccess" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1411 = "Invoke-CheckLocalAdminAccess" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1412 = "invokeenumeratelocaladmin" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1413 = "Invoke-EnumerateLocalAdmin" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1414 = /Invoke\-EnvBypass\./ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1415 = "Invoke-EventVwrBypass" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1416 = "invokefilefinder" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1417 = "Invoke-FileFinder" nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string1418 = "Invoke-HostEnum -" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1419 = "invokekerberoast" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1420 = "Invoke-Kerberoast" nocase ascii wide
        // Description: powershell function used with cobaltstrike to kill parent process
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1421 = "Invoke-ParentalKilling" nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1422 = "Invoke-Phant0m" nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1423 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1424 = "invokeprocesshunter" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1425 = "Invoke-ProcessHunter" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1426 = "invokereverttoself" nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1427 = "Invoke-RevertToSelf" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1428 = "invokesharefinder" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1429 = "Invoke-ShareFinder" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1430 = "invokestealthuserhunter" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1431 = "Invoke-StealthUserHunter" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1432 = "invokeuserhunter" nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1433 = "Invoke-UserHunter" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1434 = "Invoke-WScriptBypassUAC" nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1435 = "jas502n/bypassAV" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1436 = /java\s\-jar\sBeaconTool\.jar/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1437 = /java\s\-jar\sBeaconTool\.jar/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1438 = "Job killed and console drained" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1439 = /jquery\-c2\..{0,100}\.profile/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1440 = "jump psexec_psh" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1441 = "jump psexec64" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1442 = "jump winrm " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1443 = "jump winrm" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1444 = "jump-exec scshell" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1445 = /K8_CS_.{0,100}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1446 = /k8gege\.org\// nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1447 = "k8gege/Ladon" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1448 = /K8Ladon\.sln/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1449 = /KaliLadon\./ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1450 = /KBDPAYLOAD\.dll/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1451 = /kdstab\s.{0,100}\s\/CHECK/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1452 = /kdstab\s.{0,100}\s\/CLOSE/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1453 = /kdstab\s.{0,100}\s\/DRIVER/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1454 = /kdstab\s.{0,100}\s\/KILL/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1455 = /kdstab\s.{0,100}\s\/LIST/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1456 = /kdstab\s.{0,100}\s\/NAME/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1457 = /kdstab\s.{0,100}\s\/PID/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1458 = /kdstab\s.{0,100}\s\/SERVICE/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1459 = /kdstab\s.{0,100}\s\/STRIP/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1460 = /kdstab\s.{0,100}\s\/UNLOAD/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1461 = /kdstab\.cna/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1462 = /kerberoasting\.x64/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1463 = /Kerberos\sabuse\s\(kerbeus\sBOF\)/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1464 = /kerberos.{0,100}\.kirbi/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1465 = /Kerbeus\s.{0,100}\sby\sRalfHacker/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1466 = /kerbeus_cs\.cna/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1467 = /kerbeus_havoc\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1468 = "Kerbeus-BOF-main" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1469 = /kernelcallbacktable\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1470 = /kernelcallbacktable\.x64/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1471 = /kernelcallbacktable\.x86/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1472 = /kernelcallbacktable\.x86/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1473 = /KernelMii\.cna/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1474 = /KernelMii\.x64\.exe/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1475 = /KernelMii\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1476 = /KernelMii\.x86\.exe/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1477 = /KernelMii\.x86\.o/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1478 = "killdefender check" nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1479 = "killdefender kill" nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1480 = /KillDefender\.x64/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1481 = /KillDefender\.x64\./ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1482 = "killdefender_bof" nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1483 = "KillDefender_BOF" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1484 = /kirbi\.tickets/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1485 = "koh filter add SID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1486 = "koh filter list" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1487 = "koh filter remove SID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1488 = "koh filter reset" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1489 = "koh groups LUID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1490 = "koh impersonate LUID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1491 = "koh release all" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1492 = "koh release LUID" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1493 = /Koh\.exe\scapture/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1494 = /Koh\.exe\slist/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1495 = /Koh\.exe\smonitor/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1496 = "krb_asktgs /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1497 = "krb_asktgt /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1498 = "krb_asreproasting" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1499 = "krb_changepw /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1500 = "krb_cross_s4u /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1501 = "krb_describe /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1502 = "krb_dump /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1503 = "krb_hash /password" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1504 = "krb_klist /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1505 = "krb_ptt /ticket:" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1506 = "krb_purge /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1507 = "krb_renew /ticket:" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1508 = "krb_s4u /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1509 = "krb_tgtdeleg /" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1510 = /krb_tgtdeleg\(.{0,100}\)/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1511 = "krb_triage /" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1512 = /krb5\/kerberosv5\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1513 = "krbasktgt /" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1514 = /krbcredccache\.py/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string1515 = "kyleavery/AceLdr" nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1516 = "kyleavery/inject-assembly" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1517 = /Ladon\s.{0,100}\sAllScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1518 = /Ladon\s.{0,100}\sCiscoScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1519 = /Ladon\s.{0,100}\sOnlineIP/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1520 = /Ladon\s.{0,100}\sOnlinePC/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1521 = /Ladon\s.{0,100}\sOsScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1522 = /Ladon\s.{0,100}\sOxidScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1523 = /Ladon\s.{0,100}\.txt\s/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1524 = /Ladon\s.{0,100}DeBase64/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1525 = /Ladon\s.{0,100}FtpScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1526 = /Ladon\s.{0,100}LdapScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1527 = /Ladon\s.{0,100}SMBGhost/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1528 = /Ladon\s.{0,100}SmbHashScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1529 = /Ladon\s.{0,100}SmbScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1530 = /Ladon\s.{0,100}SshScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1531 = /Ladon\s.{0,100}TomcatScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1532 = /Ladon\s.{0,100}VncScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1533 = /Ladon\s.{0,100}WebScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1534 = /Ladon\s.{0,100}WinrmScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1535 = /Ladon\s.{0,100}WmiHashScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1536 = /Ladon\s.{0,100}WmiScan/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1537 = "Ladon ActiveAdmin" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1538 = "Ladon ActiveGuest" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1539 = "Ladon AdiDnsDump " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1540 = "Ladon at c:" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1541 = "Ladon AtExec" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1542 = "Ladon AutoRun" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1543 = "Ladon BadPotato" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1544 = "Ladon BypassUAC" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1545 = "Ladon CheckDoor" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1546 = "Ladon Clslog" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1547 = "Ladon CmdDll " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1548 = "Ladon cmdline" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1549 = "Ladon CVE-" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1550 = "Ladon DirList" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1551 = "Ladon DraytekExp" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1552 = "Ladon DumpLsass" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1553 = "Ladon EnableDotNet" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1554 = "Ladon EnumProcess" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1555 = "Ladon EnumShare" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1556 = "Ladon Exploit" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1557 = "Ladon FindIP " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1558 = "Ladon FirefoxCookie" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1559 = "Ladon FirefoxHistory" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1560 = "Ladon FirefoxPwd" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1561 = "Ladon ForExec " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1562 = "Ladon FtpDownLoad " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1563 = "Ladon FtpServer " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1564 = "Ladon GetDomainIP" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1565 = "Ladon gethtml " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1566 = "Ladon GetPipe" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1567 = "Ladon GetSystem" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1568 = "Ladon IISdoor" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1569 = "Ladon IISpwd" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1570 = "Ladon MssqlCmd " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1571 = "Ladon netsh " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1572 = "Ladon noping " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1573 = "Ladon Open3389" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1574 = "Ladon PowerCat " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1575 = "Ladon PrintNightmare" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1576 = "Ladon psexec" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1577 = "Ladon QueryAdmin" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1578 = "Ladon RdpHijack" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1579 = "Ladon ReadFile " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1580 = "Ladon RegAuto" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1581 = "Ladon ReverseHttps" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1582 = "Ladon ReverseTcp " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1583 = "Ladon RevShell-" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1584 = "Ladon Runas" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1585 = "Ladon RunPS " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1586 = "Ladon sc " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1587 = "Ladon SetSignAuth" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1588 = "Ladon SmbExec " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1589 = "Ladon Sniffer" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1590 = "Ladon SshExec " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1591 = "Ladon SweetPotato" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1592 = "Ladon TcpServer " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1593 = "Ladon UdpServer" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1594 = "Ladon WebShell" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1595 = "Ladon whoami" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1596 = "Ladon WifiPwd" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1597 = "Ladon wmiexec" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1598 = "Ladon WmiExec2 " nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1599 = "Ladon XshellPwd" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1600 = "Ladon ZeroLogon" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1601 = "Ladon40 BypassUAC" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1602 = /Ladon911.{0,100}\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1603 = /Ladon911\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1604 = /Ladon911_.{0,100}\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1605 = /LadonExp\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1606 = /LadonGUI\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1607 = /LadonLib\.rar/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1608 = /LadonStudy\.exe/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1609 = /lastpass\.x86/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1610 = /lastpass\/process_lp_files\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1611 = /ldap_shell\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1612 = /ldapattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1613 = /ldaprelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1614 = /LdapSignCheck\.exe/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1615 = /LdapSignCheck\.Natives/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1616 = /LdapSignCheck\.sln/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1617 = /ldapsigncheck\.x64\./ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1618 = /ldapsigncheck\.x86\./ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1619 = /LetMeOutSharp\./ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1620 = "libs/bofalloc" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1621 = "libs/bofentry" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1622 = "libs/bofhelper" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1623 = /LiquidSnake\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1624 = "llsrpc_##" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1625 = "load aggressor script" nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string1626 = /load_sc\.exe\s.{0,100}\.bin/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1627 = "Load-BeaconParameters" nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1628 = /Load\-Bof\(/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1629 = /loader\/loader\/loader\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1630 = /localS4U2Proxy\.tickets/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1631 = "logToBeaconLog" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1632 = "lsarpc_##" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1633 = "Magnitude Exploit Kit" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1634 = /main_air_service\-probes\.go/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1635 = /main_pro_service\-probes\.go/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1636 = /makebof\.bat/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string1637 = "Malleable C2 Files" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1638 = "Malleable PE/Stage" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1639 = /malleable_redirector\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1640 = "malleable_redirector_hidden_api_endpoint" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1641 = "Malleable-C2-Profiles" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1642 = "Malleable-C2-Randomizer" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1643 = "Malleable-C2-Randomizer" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1644 = "malleable-redirector-config" nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string1645 = "mandllinject " nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1646 = "mdsecactivebreach/CACTUSTORCH" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1647 = "med0x2e/SigFlip" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1648 = /memreader\s.{0,100}access_token/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1649 = /MemReader_BoF\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1650 = /meterpreter\./ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1651 = /metsrv\.dll/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1652 = "mgeeky/RedWarden" nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1653 = /mimipenguin\.cna/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1654 = /mimipenguin\.so/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1655 = /mimipenguin_x32\.so/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1656 = "minidump_add_memory_block" nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1657 = "minidump_add_memory64_block" nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1658 = "miscbackdoorlnkhelp" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1659 = /Mockingjay_BOF\.sln/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1660 = "Mockingjay_BOF-main" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1661 = "mojo_##" nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1662 = "moonD4rk/HackBrowserData" nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1663 = /MoveKit\-master\.zip/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1664 = /move\-msbuild\s.{0,100}\shttp\smove\.csproj/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1665 = /move\-pre\-custom\-file\s.{0,100}\.exe\s/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string1666 = "msfvemonpayload" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1667 = /mssqlattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1668 = /mssqlrelayclient\.py/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1669 = "my_dump_my_pe" nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1670 = /needle_sift\.x64/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1671 = /needlesift\.cna/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1672 = "netero1010/Quser-BOF" nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1673 = "netero1010/ServiceMove-BOF" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1674 = "netlogon_##" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1675 = "netuser_enum" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1676 = "netview_enum" nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1677 = /NoApiUser\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1678 = "noconsolation /tmp/" nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1679 = /noconsolation\s\-\-local\s.{0,100}cmd\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1680 = /noconsolation\s\-\-local\s.{0,100}powershell\.exe/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1681 = /No\-Consolation\.cna/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1682 = /NoConsolation\.x64\.o/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1683 = /NoConsolation\.x86\.o/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1684 = "No-Consolation-main" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1685 = /normal\/randomized\.profile/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1686 = /ntcreatethread\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1687 = /ntcreatethread\.x86/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1688 = /oab\-parse\.py/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1689 = "obscuritylabs/ase:latest" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1690 = "obscuritylabs/RAI/" nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1691 = "Octoberfest7/KDStab" nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1692 = "OG-Sadpanda/SharpCat" nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string1693 = "OG-Sadpanda/SharpSword" nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string1694 = "OG-Sadpanda/SharpZippo" nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1695 = /On_Demand_C2\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1696 = /On\-Demand_C2_BOF\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1697 = /OnDemandC2Class\.cs/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1698 = "openBeaconBrowser" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1699 = "openBeaconBrowser" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1700 = "openBeaconConsole" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1701 = "openBeaconConsole" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1702 = "openBypassUACDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1703 = "openBypassUACDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1704 = "openGoldenTicketDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1705 = "openKeystrokeBrowser" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1706 = "openPayloadGenerator" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1707 = "openPayloadGeneratorDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1708 = "openPayloadHelper" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1709 = "openPortScanner" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1710 = "openPortScanner" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1711 = "openSpearPhishDialog" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1712 = "openWindowsExecutableStage" nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string1713 = "optiv/Registry-Recon" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1714 = "optiv/ScareCrow" nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1715 = /Outflank\-Dumpert\./ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1716 = "outflanknl/Recon-AD" nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string1717 = "outflanknl/Spray-AD" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string1718 = "outflanknl/WdToggle" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1719 = "Outflank-Recon-AD" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1720 = /output\/html\/data\/beacons\.json/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1721 = "output/payloads/" nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1722 = /package\scom\.blackh4t/ nocase ascii wide
        // Description: CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1723 = /parse\sthe\s\.beacon_keys\sto\sRSA\sprivate\skey\sand\spublic\skey\sin\spem\sformat/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1724 = "parse_aggressor_properties" nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1725 = "parse_shellcode" nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1726 = "patchAmsiOpenSession" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1727 = "payload_bootstrap_hint" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1728 = "payload_local" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1729 = /payload_scripts\.cna/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1730 = "payload_scripts/sleepmask" nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1731 = /payload_section\.cpp/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1732 = /payload_section\.hpp/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1733 = /payloadgenerator\.py/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1734 = "Perform AS-REP roasting" nocase ascii wide
        // Description: cobaltstrike plugin (This reads an ADFIND dump and CSVs it) used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1735 = /perl\sadcsv\.pl\s/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1736 = /PersistBOF\.cna/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1737 = /PersistenceBOF\.c/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1738 = /PersistenceBOF\.exe/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1739 = /persist\-ice\-junction\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1740 = /persist\-ice\-monitor\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1741 = /persist\-ice\-shortcut\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1742 = /persist\-ice\-time\.o/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1743 = /persist\-ice\-xll\.o/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1744 = "Phant0m_cobaltstrike" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1745 = "'pipename_stager'" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1746 = "Pitty Tiger RAT" nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1747 = /\-pk8gege\.org/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1748 = /pkexec64\.tar\.gz/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1749 = /plug_getpass_nps\.dll/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1750 = /plug_katz_nps\.exe/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1751 = /plug_qvte_nps\.exe/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1752 = "PoolParty attack completed successfully" nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1753 = "PoolPartyBof " nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1754 = /PoolPartyBof\s.{0,100}\sHTTPSLocal/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1755 = /PoolPartyBof\.cna/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1756 = "PoolPartyBof-main" nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1757 = "PortBender backdoor" nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1758 = "PortBender redirect" nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1759 = /PortBender\.cna/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1760 = /PortBender\.cpp/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1761 = /portbender\.dll/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1762 = /PortBender\.exe/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1763 = /PortBender\.h/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1764 = /PortBender\.sln/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1765 = /PortBender\.zip/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1766 = /portscan_result\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1767 = "portscan386 " nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1768 = "portscan64 " nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1769 = "post_ex_amsi_disable" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1770 = "post_ex_keylogger" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1771 = "post_ex_obfuscate" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1772 = "Post_EX_Process_Name" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1773 = "post_ex_smartinject" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1774 = "post_ex_spawnto_x64" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1775 = "post_ex_spawnto_x86" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1776 = "powershell_encode_oneliner" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1777 = "powershell_encode_oneliner" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1778 = "powershell_encode_stager" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1779 = "powershell_encode_stager" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1780 = /powershell\-import\s.{0,100}\.ps1/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1781 = "PowerView3-Aggressor" nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1782 = /ppenum\.c/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1783 = /ppenum\.exe/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1784 = /ppenum\.x64\./ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1785 = /ppenum\.x86\./ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1786 = /ppl_dump\.x64/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1787 = "ppldump " nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1788 = /PPLDump_BOF\./ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1789 = /pplfault\.cna/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1790 = "PPLFaultDumpBOF" nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1791 = /PPLFaultPayload\.dll/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1792 = "PPLFaultTemp" nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1793 = /praetorian\.antihacker/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1794 = "praetorian-inc/PortBender" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1795 = "prepareResponseForHiddenAPICall" nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1796 = "PrintSpoofer-" nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1797 = /PrintSpoofer\./ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1798 = /process_imports\.cna/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1799 = /process_imports\.x64/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1800 = /process_imports_api\s.{0,100}\.exe/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1801 = "process_inject_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1802 = "process_inject_bof_allocator" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1803 = "process_inject_bof_reuse_memory" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1804 = "process_inject_execute" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1805 = "process_inject_min_alloc" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1806 = "process_inject_startrwx" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1807 = "Process_Inject_Struct" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1808 = "process_inject_transform_x" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1809 = "process_inject_userwx" nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1810 = "process_protection_enum " nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1811 = /process_protection_enum.{0,100}\.dmp/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1812 = /process_protection_enum\./ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1813 = /Process_Protection_Level_BOF\./ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1814 = "Process_Protection_Level_BOF/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1815 = /ProcessDestroy\.x64/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1816 = /ProcessDestroy\.x64\./ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1817 = /ProcessDestroy\.x86/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1818 = /ProcessDestroy\.x86\./ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1819 = "process-inject " nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1820 = "processinject_min_alloc" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1821 = /ProgIDsUACBypass\./ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1822 = "Proxy Shellcode Handler" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1823 = /proxychains.{0,100}scshell/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1824 = "proxyshellcodeurl" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1825 = /PSconfusion\.py/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1826 = "PSEXEC_PSH " nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/pureqh/bypassAV
        $string1827 = "pureqh/bypassAV" nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1828 = "pwn1sher/CS-BOFs" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1829 = /pycobalt\./ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1830 = "pycobalt/aggressor" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1831 = "pycobalt_debug_on" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1832 = "pycobalt_path" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1833 = "pycobalt_python" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1834 = "pycobalt_timeout" nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1835 = "pyMalleableC2" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1836 = "pystinger_for_darkshadow" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1837 = "python scshell" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1838 = /python2\?\?\/generator\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1839 = /python2\?\?\/PyLoader\.py/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1840 = "python3 scshell" nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1841 = /python3\?\?\/generator\.py/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1842 = /python3\?\?\/PyLoader\.py/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1843 = "QUAPCInjectAsSystem" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1844 = "QUAPCInjectElevated" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1845 = "QUAPCInjectFakecmd" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1846 = "QUAPCInjectFakecmd" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1847 = "QUAPCInjectWithoutPid" nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1848 = /quser\.x64\.o/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1849 = /quser\.x86\.o/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1850 = "QXh4OEF4eDhBeHg4QXh4OA==" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1851 = "RAI/ase_docker" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1852 = /rai\-attack\-servers\./ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1853 = "rai-redirector-dns" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1854 = "rai-redirector-http" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1855 = "RalfHacker/Kerbeus-BOF" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1856 = "random_c2_profile" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1857 = /random_c2profile\./ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1858 = /random_user_agent\.params/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1859 = /random_user_agent\.user_agent/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1860 = "rasta-mouse/PPEnum" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1861 = "rasta-mouse/TikiTorch" nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1862 = /rdi_net_user\.cpp/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1863 = /rdphijack\.x64/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1864 = /rdphijack\.x86/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1865 = "RDPHijack-BOF" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1866 = /RdpThief\./ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1867 = "read_cs_teamserver" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1868 = /Recon\-AD\-.{0,100}\.dll/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1869 = /Recon\-AD\-.{0,100}\.sln/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1870 = /Recon\-AD\-.{0,100}\.vcxproj/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1871 = "Recon-AD-AllLocalGroups" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1872 = "Recon-AD-Domain" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1873 = "Recon-AD-LocalGroups" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1874 = "Recon-AD-SPNs" nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1875 = /Recon\-AD\-Users\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1876 = "redelk_backend_name_c2" nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1877 = "redelk_backend_name_decoy" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1878 = /Red\-Team\-Infrastructure\-Wiki\./ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1879 = /RedWarden\.py/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1880 = /RedWarden\.test/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1881 = /redwarden_access\.log/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1882 = /redwarden_redirector\.log/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1883 = /reflective_dll\.dll/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1884 = /reflective_dll\.x64\.dll/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1885 = /ReflectiveDll\.x64\.dll/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1886 = /ReflectiveDll\.x86\.dll/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1887 = "Reflective-HackBrowserData" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1888 = /Remote\/lastpass\/lastpass\.x86\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1889 = "Remote/setuserpass/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1890 = "Remote/shspawnas" nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1891 = "Remote/suspendresume/" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1892 = /remote\-exec\s.{0,100}jump\s/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1893 = /remotereg\.cna/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1894 = "replace_key_iv_shellcode" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1895 = "RiccardoAncarani/BOFs" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1896 = "RiccardoAncarani/LiquidSnake" nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string1897 = "RiccardoAncarani/TaskShell" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1898 = "rkervella/CarbonMonoxide" nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1899 = "rookuu/BOFs/" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1900 = /rpcattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1901 = /rpcrelayclient\.py/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1902 = "rsmudge/ElevateKit" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1903 = "runasadmin uac-cmstplua" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1904 = "runasadmin uac-token-duplication" nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1905 = /RunOF\.exe\s\-/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1906 = /RunOF\.Internals/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1907 = /rustbof\.cna/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1908 = "rvrsh3ll/BOF_Collection" nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1909 = "rxwx/cs-rdll-ipc-example" nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1910 = /s4u\.x64\.c/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1911 = /s4u\.x64\.o/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1912 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1913 = /SamAdduser\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1914 = "samr_##" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1915 = /ScareCrow.{0,100}\s\-encryptionmode\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1916 = /ScareCrow.{0,100}\s\-Evasion/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1917 = /ScareCrow.{0,100}\s\-Exec/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1918 = /ScareCrow.{0,100}\s\-injection/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1919 = /ScareCrow.{0,100}\s\-Loader\s.{0,100}\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1920 = /ScareCrow.{0,100}\s\-noamsi/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1921 = /ScareCrow.{0,100}\s\-noetw/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1922 = /ScareCrow.{0,100}\s\-obfu/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1923 = /ScareCrow.{0,100}_darwin_amd64/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1924 = /ScareCrow.{0,100}_windows_amd64\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1925 = /ScareCrow.{0,100}KnownDLL/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1926 = /ScareCrow.{0,100}ProcessInjection/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1927 = /ScareCrow\.cna/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1928 = "ScareCrow/Cryptor" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1929 = "ScareCrow/limelighter" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1930 = "ScareCrow/Loader" nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1931 = "ScareCrow/Utils" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1932 = /schshell\.cna/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1933 = "schtask_callback" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1934 = "schtasks_elevator" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1935 = "schtasks_exploit " nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1936 = /ScRunBase32\.exe/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1937 = /ScRunBase32\.py/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1938 = /ScRunBase64\.exe/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1939 = /ScRunBase64\.py/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1940 = /scshell.{0,100}XblAuthManager/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1941 = /SCShell\.exe/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1942 = /scshell\.py/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1943 = /scshellbof\.c/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1944 = /scshellbof\.o/ nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1945 = "scshellbofx64" nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1946 = "searchsploit_rc" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1947 = /Seatbelt\.exe/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1948 = "sec-inject " nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1949 = /secinject\.cna/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1950 = /secinject\.git/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1951 = /secinject\.x64/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1952 = /secinject\.x86/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1953 = "secinject/src" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1954 = /secretsdump\..{0,100}\.pyc/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1955 = /secretsdump\.py/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1956 = "sec-shinject " nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1957 = /self_delete\.x64\.o/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1958 = "Self_Deletion_BOF" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1959 = "send_shellcode_via_pipe" nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1960 = "send_shellcode_via_pipe" nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1961 = /serverscan\.linux\.elf/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1962 = /serverscan\.linux\.so/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1963 = /serverScan\.win\.cna/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1964 = /serverscan_386\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1965 = /ServerScan_Air_.{0,100}\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1966 = /ServerScan_Air_.{0,100}_amd64/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1967 = /ServerScan_Air_.{0,100}_i386/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1968 = /serverscan_air\-probes\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1969 = /serverscan_amd64\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1970 = /ServerScan_Pro_.{0,100}\.exe/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1971 = /ServerScan_Pro_.{0,100}_amd64/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1972 = /ServerScan_Pro_.{0,100}_i386/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1973 = "serverscan64 " nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1974 = /serverscan64\s.{0,100}tcp/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1975 = "serverscan86 " nocase ascii wide
        // Description: New Lateral Movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1976 = /servicemove.{0,100}hid\.dll/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1977 = "set hosts_stage" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1978 = "set keylogger" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1979 = "set obfuscate " nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1980 = "set pipename " nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1981 = "set smartinject" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1982 = "set userwx" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1983 = "setc_webshell" nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1984 = "setLoaderFlagZero" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1985 = /setthreadcontext\.x64/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1986 = /setthreadcontext\.x86/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1987 = "setup_obfuscate_xor_key" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1988 = "setup_reflective_loader" nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1989 = "seventeenman/CallBackDump" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1990 = /ShadowUser\/scvhost\.exe/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string1991 = /SharpCalendar\.exe/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1992 = /SharpCat\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1993 = /sharpcompile.{0,100}\.exe/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1994 = "sharpCompileHandler" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1995 = "SharpCompileServer" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1996 = /SharpCompileServer\.exe/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1997 = /SharpCradle.{0,100}logonpasswords/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1998 = /SharpCradle\.exe/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string1999 = "SharpEventLoader" nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string2000 = "SharpEventPersist" nocase ascii wide
        // Description: Read Excel Spreadsheets (XLS/XLSX) using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpExcelibur
        $string2001 = "SharpExcelibur" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2002 = "sharp-exec " nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2003 = "sharp-fexec " nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2004 = /SharpGen\.dll/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2005 = /sharpgen\.enable_cache/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2006 = /sharpgen\.py/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2007 = /sharpgen\.set_location/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string2008 = "Sharp-HackBrowserData" nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2009 = /SharpHound\.cna/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2010 = /SharpHound\.exe/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2011 = /SharpHound\.ps1/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2012 = /Sharphound2\./ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2013 = "Sharphound-Aggressor" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2014 = "SharpSCShell" nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string2015 = "SharpSploitConsole_x" nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string2016 = /SharpStay\.exe/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string2017 = /SharpSword\.exe/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2018 = "SharpZeroLogon" nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string2019 = /SharpZippo\.exe/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string2020 = /shell\.exe\s\-s\spayload\.txt/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string2021 = /Shellcode_encryption\.exe/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string2022 = /shellcode_generator\./ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string2023 = /shellcode_generator_help\.html/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string2024 = /ShellCode_Loader\.py/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2025 = /shellcode20\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2026 = /shellcode30\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2027 = /shellcode35\.exe/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2028 = /shellcode40\.exe/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2029 = "shspawn x64 " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2030 = "shspawn x86 " nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2031 = /SigFlip\.exe\s\-/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2032 = /SigFlip\.WinTrustData/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2033 = /SigInject\s.{0,100}\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2034 = /Sigloader\s.{0,100}\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2035 = /SigLoader\/sigloader\.c/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2036 = /sigwhatever\.exe/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string2037 = "Silent Lsass Dump" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string2038 = "silentLsassDump" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2039 = "-Situational-Awareness-BOF" nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2040 = /sleep_python_bridge\.sleepy/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2041 = /sleep_python_bridge\.striker/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2042 = /sleepmask\.x64\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2043 = /sleepmask\.x86\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2044 = /sleepmask_pivot\.x64\.o/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2045 = /sleepmask_pivot\.x86\.o/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2046 = "smb_pipename_stager" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2047 = /smbattack\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2048 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2049 = /smbrelayserver\./ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2050 = /smtprelayclient\.py/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2051 = "socky whoami" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2052 = /SourcePoint.{0,100}Loader\.go/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2053 = /source\-teamserver\.sh/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string2054 = "spawn/runshellcode" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2055 = /SpawnTheThing\(/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2056 = /spawnto\s.{0,100}\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2057 = "'spawnto_x64'" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2058 = "'spawnto_x86'" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2059 = "spoolss_##" nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2060 = "spoolsystem inject" nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2061 = "spoolsystem spawn" nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2062 = /spoolsystem\.cna/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2063 = /SpoolTrigger\.x64\.dl/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2064 = /SpoolTrigger\.x64\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2065 = /SpoolTrigger\.x86\.dl/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2066 = /SpoolTrigger\.x86\.dll/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2067 = /SpoolTrigger\\SpoolTrigger\./ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2068 = "Spray-AD " nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2069 = /Spray\-AD\.cna/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2070 = /Spray\-AD\.dll/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2071 = /Spray\-AD\.exe/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2072 = /Spray\-AD\.sln/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2073 = /Spray\-AD\\Spray\-AD/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2074 = "src/Remote/chromeKey/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2075 = "src/Remote/lastpass/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2076 = "src/Remote/sc_config/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2077 = "src/Remote/sc_create/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2078 = "src/Remote/sc_delete/" nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2079 = "src/Remote/sc_start/" nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2080 = "Src/Spray-AD" nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2081 = /src\/zerologon\.c/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string2082 = /src\\unhook\.c/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2083 = "srvsvc_##" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2084 = /stage\.obfuscate/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2085 = "stage_smartinject" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2086 = "stage_transform_x64_prepend" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2087 = "stage_transform_x64_strrep1" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2088 = "stage_transform_x86_prepend" nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2089 = "stage_transform_x86_strrep1" nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string2090 = "stageless payload" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2091 = "stager_bind_pipe" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2092 = "stager_bind_pipe" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2093 = "stager_bind_tcp" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2094 = "stager_bind_tcp" nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2095 = "start stinger " nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string2096 = "Starting PoolParty attack against process id:" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2097 = /StartProcessFake\(/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2098 = "static_syscalls_apc_spawn " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2099 = "static_syscalls_apc_spawn" nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2100 = "static_syscalls_dump" nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2101 = /StayKit\.cna/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2102 = /StayKit\.exe/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2103 = /StayKit\.git/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2104 = /steal_token\(/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2105 = "steal_token_access_mask" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2106 = "stinger_client -" nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2107 = /stinger_client\.py/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2108 = /stinger_server\.exe/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2109 = /strip_bof\.ps1/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2110 = "strip-bof -Path " nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2111 = /sudo\s\.\/teamserver\s/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2112 = /suspendresume\.x64\./ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2113 = /suspendresume\.x86\./ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2114 = "SW2_GetSyscallNumber" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2115 = "SW2_HashSyscall" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2116 = "SW2_PopulateSyscallList" nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2117 = "SW2_RVA2VA" nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2118 = /SwampThing\.exe/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2119 = /SweetPotato\.cna/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2120 = /SweetPotato\.csproj/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2121 = /SweetPotato\.exe/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2122 = /SweetPotato\.ImpersonationToken/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2123 = /SweetPotato\.sln/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2124 = "syscall_disable_priv " nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2125 = "syscall_enable_priv " nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2126 = /syscalls\.asm/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2127 = /syscalls_dump\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2128 = "syscalls_inject " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2129 = /syscalls_inject\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2130 = "syscalls_shinject " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2131 = "syscalls_shspawn " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2132 = "syscalls_spawn " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2133 = /syscalls_spawn\./ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2134 = /syscallsapcspawn\.x64/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2135 = /syscalls\-asm\.h/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2136 = /syscallsdump\.x64/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2137 = /syscallsinject\.x64/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2138 = /syscallsspawn\.x64/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2139 = /systemctl\senable\steamserver\.service/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2140 = /systemctl\sstart\steamserver\.service/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2141 = /systemctl\sstatus\steamserver\.service/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2142 = /SysWhispers\.git\s/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2143 = /syswhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2144 = /syswhispers\.py/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2145 = "SysWhispers2" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2146 = /TailorScan\.exe\s/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2147 = "TailorScan_darwin" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2148 = "TailorScan_freebsd" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2149 = "TailorScan_linux_" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2150 = "TailorScan_netbsd_" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2151 = "TailorScan_openbsd_" nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2152 = /TailorScan_windows_.{0,100}\.exe/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2153 = /TaskShell\.exe\s.{0,100}\s\-b\s.{0,100}\.exe/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2154 = /TaskShell\.exe\s.{0,100}\s\-s\s.{0,100}SYSTEM/ nocase ascii wide
        // Description: teamserver cobaltstrike
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2155 = /teamserver\s.{0,100}\sc2\-profiles\// nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string2156 = /teamserver.{0,100}\sno_evasion\.profile/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string2157 = /TeamServer\.prop/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string2158 = /Temp\\dumpert/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string2159 = /test_invoke_bof\.x64\.o/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2160 = "tgtdelegation " nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2161 = /tgtdelegation\.cna/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2162 = /tgtdelegation\.x64/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2163 = /tgtdelegation\.x86/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2164 = /tgtParse\.py\s/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2165 = "third_party/SharpGen" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2166 = /third\-party.{0,100}winvnc.{0,100}\.dll/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2167 = /threatexpress.{0,100}malleable/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string2168 = "threatexpress/cs2modrewrite" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2169 = /ticketConverter\.py\s.{0,100}\.ccache\s/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string2170 = "tijme/kernel-mii" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2171 = /TikiLoader.{0,100}Hollower/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2172 = /TikiLoader\./ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2173 = /TikiLoader\./ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2174 = /TikiLoader\.dll/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2175 = /TikiLoader\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2176 = /TikiLoader\.Injector/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2177 = /TikiLoader\\TikiLoader/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2178 = /TikiSpawn\.dll/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2179 = /TikiSpawn\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2180 = /TikiSpawn\.ps1/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2181 = "TikiSpawnAs" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2182 = "TikiSpawnAsAdmin" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2183 = "TikiSpawnElevated" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2184 = "TikiSpawnWOppid" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2185 = "TikiSpawnWppid" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2186 = /TikiTorch\.exe/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2187 = /TikiVader\./ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2188 = "timwhitez/Doge-Loader" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2189 = /Tmprovider\.dll/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2190 = /toggle_privileges\.cna/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2191 = /toggle_privileges_bof\./ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2192 = "Toggle_Token_Privileges_BOF" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2193 = "ToggleWDigest" nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string2194 = "TokenStripBOF/src" nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2195 = "token-vault steal" nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2196 = /token\-vault\.cna/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2197 = /token\-vault\.x64\.o/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2198 = /token\-vault\.x86\.o/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string2199 = "trainr3kt/MemReader_BoF" nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string2200 = "trainr3kt/Readfile_BoF" nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2201 = "TrustedPath-UACBypass-BOF" nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2202 = "Tycx2ry/SweetPotato" nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2203 = "Tylous/SourcePoint" nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2204 = "UACBypass-BOF" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2205 = "uac-schtasks " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2206 = "uac-schtasks" nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string2207 = "uac-silentcleanup" nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2208 = "uac-token-duplication" nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2209 = /uhttpsharp\./ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2210 = "uknowsec/TailorScan" nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2211 = "UMJjAiNUUtvNww0lBj9tzWegwphuIn6hNP9eeIDfOrcHJ3nozYFPT-Jl7WsmbmjZnQXUesoJkcJkpdYEdqgQFE6QZgjWVsLSSDonL28DYDVJ" nocase ascii wide
        // Description: Fileless Lateral Movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2212 = "Un1k0d3r/SCShell" nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string2213 = /ursnif_IcedID\.profile/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2214 = "Visual-Studio-BOF-template" nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2215 = /vssenum\.x64\./ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2216 = /vssenum\.x86\./ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string2217 = "vysecurity/ANGRYPUPPY" nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2218 = /wcfrelayserver\.py/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2219 = "wdigest!g_fParameter_UseLogonCredential" nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2220 = "wdigest!g_IsCredGuardEnabled" nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2221 = /whereami\.cna/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2222 = /whereami\.x64/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2223 = "WhoamiGetTokenInfo" nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2224 = /wifidump\.cna/ nocase ascii wide
        // Description: cobaltstrike default content strings
        // Reference: https://www.cobaltstrike.com/
        $string2225 = "windows/beacon_smb/" nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string2226 = /windows\-exploit\-suggester\./ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2227 = "winrmdll " nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2228 = /winrmdll\./ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2229 = "Winsocky-main" nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string2230 = "WKL-Sec/HiddenDesktop" nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2231 = "WKL-Sec/Winsocky" nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2232 = "wkssvc_##" nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string2233 = /Wmi_Persistence\.ps1/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2234 = /wmi\-event\-lateral\-movement\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2235 = /WMI\-EventSub\.cpp/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2236 = /wmi\-lateral\-movement\./ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2237 = /WMI\-ProcessCreate\.cpp/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string2238 = "write_cs_teamserver" nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2239 = "WriteAndExecuteShellcode" nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string2240 = "WritePayloadDllTransacted" nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2241 = "wscript_elevator" nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string2242 = "wts_enum_remote_processes" nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string2243 = "wumb0/rust_bof" nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string2244 = "xforcered/CredBandit" nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/xforcered/Detect-Hooks
        $string2245 = "xforcered/Detect-Hooks" nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2246 = /xor\.exe\s.{0,100}\.txt/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string2247 = "xor_payload" nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2248 = /xpipe\s\\\\/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2249 = /xpipe.{0,100}lsass/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2250 = /xpipe\.cna/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string2251 = /YDHCUI\/csload\.net/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string2252 = "YDHCUI/manjusaka" nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string2253 = "youcantpatchthis" nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2254 = /ysoserial\.exe/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2255 = "YwBhAGwAYwA=" nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2256 = /zerologon\.x64/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2257 = /zerologon\.x86/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2258 = "ZeroLogon-BOF" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2259 = "zha0gongz1" nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2260 = "zha0gongz1/DesertFox" nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2261 = "ziiiiizzzb" nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2262 = "ziiiiizzzib" nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2263 = /\\\\demoagent_11/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2264 = /\\\\demoagent_22/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2265 = /\\\\DserNamePipe/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2266 = /\\\\f4c3/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2267 = /\\\\f53f/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2268 = /\\\\fullduplex_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2269 = /\\\\interprocess_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2270 = /\\\\mojo_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2271 = /\\\\msagent_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2272 = /\\\\MsFteWds/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2273 = /\\\\MSSE\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2274 = /\\\\mypipe\-/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2275 = /\\\\PGMessagePipe/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2276 = /\\\\postex_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2277 = /\\\\postex_ssh_/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2278 = /\\\\SearchTextHarvester/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2279 = /\\\\UIA_PIPE/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2280 = /\\\\Winsock2\\CatalogChangeListener\-/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2281 = /\\Ladon\s.{0,100}\.exe/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string2282 = "detect-hooks" nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2283 = /doc\.1a\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2284 = /doc\.4a\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2285 = /doc\.bc\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2286 = /doc\.md\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2287 = /doc\.po\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2288 = /doc\.tx\..{0,100}\\\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2289 = /doc\-stg\-prepend.{0,100}\./ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2290 = /doc\-stg\-sh.{0,100}\./ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2291 = "dumpwifi " nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2292 = "etw stop" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2293 = "fw_walk display" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2294 = "fw_walk status" nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2295 = "fw_walk total" nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2296 = "get-spns " nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string2297 = "koh exit" nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string2298 = "koh list" nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2299 = /Ladon\sMac\s.{0,100}\s/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string2300 = "LdapSignCheck " nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2301 = /load\s.{0,100}\.cna/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string2302 = "make_token " nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string2303 = "needle_sift " nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string2304 = "remotereg " nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string2305 = /scrun\.exe\s/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2306 = /SigFlip\s.{0,100}\.exe/ nocase ascii wide
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
