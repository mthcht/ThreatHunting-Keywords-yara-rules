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
        $string1 = /.{0,1000}\s\$exploit_oneliner.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2 = /.{0,1000}\s\$payload_oneliner\s.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string3 = /.{0,1000}\s.{0,1000}\/lsass\.o.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string4 = /.{0,1000}\s\.beacon_keys\s\-.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string5 = /.{0,1000}\s\/NAME:.{0,1000}\s\/KILL.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string6 = /.{0,1000}\s\/PID:.{0,1000}\s\/DRIVER:.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string7 = /.{0,1000}\s\/PID:.{0,1000}\s\/KILL.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string8 = /.{0,1000}\s\/ticket:.{0,1000}\s\/service:.{0,1000}\s\/targetdomain:.{0,1000}\s\/targetdc:.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string9 = /.{0,1000}\s\/user:.{0,1000}\s\/password:.{0,1000}\s\/enctype:.{0,1000}\s\/opsec\s\/ptt.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string10 = /.{0,1000}\s1\.2\.3\.4:8080.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string11 = /.{0,1000}\s4444\smeter/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string12 = /.{0,1000}\s4444\sshell/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string13 = /.{0,1000}\samsi_disable\s.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string14 = /.{0,1000}\sarp\.x64\.o/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string15 = /.{0,1000}\s\-\-assemblyargs\sAntiVirus.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string16 = /.{0,1000}\s\-\-assemblyargs\sAppLocker.{0,1000}/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string17 = /.{0,1000}\sbase64_encode_shellcode.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string18 = /.{0,1000}\sbeacon\.dll.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string19 = /.{0,1000}\sbof_allocator\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string20 = /.{0,1000}\sbof_reuse_memory\s.{0,1000}/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string21 = /.{0,1000}\s\-BOFBytes\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string22 = /.{0,1000}\sBOFNET\s.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string23 = /.{0,1000}\sBofRunner\(.{0,1000}/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string24 = /.{0,1000}\sbuild\sDent\.go.{0,1000}/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string25 = /.{0,1000}\sbuild_letmeout.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string26 = /.{0,1000}\sBypassUac.{0,1000}\.bat.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string27 = /.{0,1000}\sBypassUac.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string28 = /.{0,1000}\sBypassUac.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string29 = /.{0,1000}\s\-c\sCredEnum\.c.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string30 = /.{0,1000}\schrome\slogindata\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string31 = /.{0,1000}\schrome\smasterkey\s.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string32 = /.{0,1000}\s\-cobalt\s.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string33 = /.{0,1000}\scobaltstrike.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string34 = /.{0,1000}\sCoffeeExecuteFunction.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string35 = /.{0,1000}\scom\.blackh4t.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string36 = /.{0,1000}\sCrossC2\sListener.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string37 = /.{0,1000}\sCrossC2\..{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string38 = /.{0,1000}\sCrossC2Kit\s.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string39 = /.{0,1000}\sDelegationBOF\.c\s.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string40 = /.{0,1000}\sdelegationx64\.o.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string41 = /.{0,1000}\sdelegationx86\.o.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string42 = /.{0,1000}\sDesertFox\.go/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string43 = /.{0,1000}\sdetect\-hooks\.c\s.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string44 = /.{0,1000}\s\-dns_stager_prepend\s.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string45 = /.{0,1000}\s\-dns_stager_subhost\s.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string46 = /.{0,1000}\s\-\-dotnetassembly\s.{0,1000}\s\-\-amsi.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string47 = /.{0,1000}\s\-\-dotnetassembly\s.{0,1000}\s\-\-appdomain\s.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string48 = /.{0,1000}\s\-\-dotnetassembly\s.{0,1000}\s\-\-assemblyargs\s.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string49 = /.{0,1000}\s\-\-dotnetassembly\s.{0,1000}\s\-\-mailslot.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string50 = /.{0,1000}\s\-\-dotnetassembly\s.{0,1000}\s\-\-pipe\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string51 = /.{0,1000}\sDraytekScan.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string52 = /.{0,1000}\sdump_memory64.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string53 = /.{0,1000}\sedge\slogindata\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string54 = /.{0,1000}\sedge\smasterkey\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string55 = /.{0,1000}\sEfsPotato.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string56 = /.{0,1000}\sexclusion\.c\s\/Fodefender\.o.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string57 = /.{0,1000}\s\-FakeCmdLine\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string58 = /.{0,1000}\sFileZillaPwd.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string59 = /.{0,1000}\sforgeTGT\(.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string60 = /.{0,1000}\sFtpSniffer\s.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string61 = /.{0,1000}\sgenerate_my_dll.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string62 = /.{0,1000}\sgeneratePayload.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string63 = /.{0,1000}\sGetAppLockerPolicies.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string64 = /.{0,1000}\sGetLsassPid.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string65 = /.{0,1000}\sgophish\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string66 = /.{0,1000}\sHackBrowserData.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string67 = /.{0,1000}\s\-hasbootstraphint\s.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string68 = /.{0,1000}\sHiddenDesktop\.cna.{0,1000}/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string69 = /.{0,1000}\shollow\.x64\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string70 = /.{0,1000}\shostenum\.py\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string71 = /.{0,1000}\sHTTPSniffer\s.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string72 = /.{0,1000}\s\-i\shavex\.profile\s.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string73 = /.{0,1000}\simpacket\s.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string74 = /.{0,1000}\s\-Injector\sNtMapViewOfSection.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string75 = /.{0,1000}\s\-Injector\sVirtualAllocEx.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string76 = /.{0,1000}\s\-isbeacon\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string77 = /.{0,1000}\sJspShell\sua.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string78 = /.{0,1000}\sk8gege520\s.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string79 = /.{0,1000}\skdbof\.cpp.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string80 = /.{0,1000}\sLadon\.ps1.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string81 = /.{0,1000}\sLadon\.py.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string82 = /.{0,1000}\s\-\-load\-shellcode\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string83 = /.{0,1000}\smalleable\.profile.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string84 = /.{0,1000}\smalleable\-c2\-randomizer.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string85 = /.{0,1000}\smemreader\.c\s.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string86 = /.{0,1000}\sMemReader_BoF.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string87 = /.{0,1000}\sms17010\s\-i\s.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string88 = /.{0,1000}\sms17010\s\-n\s.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string89 = /.{0,1000}\sNTLMv1\scaptured\s.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string90 = /.{0,1000}\s\-o\s\/share\/payloads\/.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string91 = /.{0,1000}\soxidfind\s\-i\s.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string92 = /.{0,1000}\soxidfind\s\-n\s.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string93 = /.{0,1000}\s\-\-payload\-types\sall.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string94 = /.{0,1000}\s\-\-payload\-types\sbin.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string95 = /.{0,1000}\s\-\-payload\-types\sdll.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string96 = /.{0,1000}\s\-\-payload\-types\sexe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string97 = /.{0,1000}\s\-\-payload\-types\sps1.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string98 = /.{0,1000}\s\-\-payload\-types\spy.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string99 = /.{0,1000}\s\-\-payload\-types\ssvc\.exe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string100 = /.{0,1000}\s\-\-payload\-types\svbs.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string101 = /.{0,1000}\s\-PE_Clone\s.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string102 = /.{0,1000}\sPerform\sS4U\sconstrained\sdelegation\sabuse.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string103 = /.{0,1000}\spipename_stager\s.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string104 = /.{0,1000}\s\-pipename_stager\s.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string105 = /.{0,1000}\spyasn1\s.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string106 = /.{0,1000}\spyasn1\..{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string107 = /.{0,1000}\srai\-attack\-dns.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string108 = /.{0,1000}\srai\-attack\-http.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string109 = /.{0,1000}\sReadFromLsass.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string110 = /.{0,1000}\s\-RealCmdLine\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string111 = /.{0,1000}\srustbof\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string112 = /.{0,1000}\sScareCrow\.go.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string113 = /.{0,1000}\sScareCrow\.go.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string114 = /.{0,1000}\sSeriousSam\.Execute\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string115 = /.{0,1000}\sSetMzLogonPwd\s.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string116 = /.{0,1000}\ssigflip\.c\s.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string117 = /.{0,1000}\sSigFlip\.exe.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string118 = /.{0,1000}\sSigFlip\.PE.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string119 = /.{0,1000}\ssigflip\.x64\..{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string120 = /.{0,1000}\ssigflip\.x86\..{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string121 = /.{0,1000}\sSigLoader\s.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string122 = /.{0,1000}\sSigwhatever.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string123 = /.{0,1000}\sspawn\.x64\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string124 = /.{0,1000}\sspawn\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string125 = /.{0,1000}\sspawnto_x64\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string126 = /.{0,1000}\sspawnto_x86\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string127 = /.{0,1000}\sSpoolFool\s.{0,1000}\.dll/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string128 = /.{0,1000}\sStayKit\.cna.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string129 = /.{0,1000}\sstriker\.py.{0,1000}/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string130 = /.{0,1000}\sSweetPotato\sby\s\@_EthicalChaos.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string131 = /.{0,1000}\sSysWhispers.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string132 = /.{0,1000}\sTikiLoader.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string133 = /.{0,1000}\sTokenStrip\.c\s.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string134 = /.{0,1000}\sTokenStripBOF\.o\s.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string135 = /.{0,1000}\sTSCHRPCAttack.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string136 = /.{0,1000}\s\-urlcache\s.{0,1000}\/debase64\/.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string137 = /.{0,1000}\s\-wordlist\s.{0,1000}\s\-spawnto\s.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string138 = /.{0,1000}\sWriteToLsass.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string139 = /.{0,1000}\sxpipe.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string140 = /.{0,1000}\$C2_SERVER.{0,1000}/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string141 = /.{0,1000}\%comspec\%\s\/k\s.{0,1000}\.bat.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string142 = /.{0,1000}\.\/c2lint\s.{0,1000}/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string143 = /.{0,1000}\.\/Dent\s\-.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string144 = /.{0,1000}\.\/manjusaka.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string145 = /.{0,1000}\.\/ScareCrow\s.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string146 = /.{0,1000}\.\/SourcePoint\s.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string147 = /.{0,1000}\.admin\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string148 = /.{0,1000}\.api\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string149 = /.{0,1000}\.apps\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string150 = /.{0,1000}\.beta\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string151 = /.{0,1000}\.blog\.123456\..{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string152 = /.{0,1000}\.cobaltstrike.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string153 = /.{0,1000}\.cobaltstrike\.beacon_keys.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string154 = /.{0,1000}\.com\/dcsync\/.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string155 = /.{0,1000}\.dev\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string156 = /.{0,1000}\.events\.123456\..{0,1000}/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string157 = /.{0,1000}\.exe\s.{0,1000}\s\-eventlog\s.{0,1000}Key\sManagement\sService.{0,1000}/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string158 = /.{0,1000}\.exe\s.{0,1000}\s\-\-source\sPersistence.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string159 = /.{0,1000}\.feeds\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string160 = /.{0,1000}\.files\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string161 = /.{0,1000}\.forums\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string162 = /.{0,1000}\.ftp\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string163 = /.{0,1000}\.go\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string164 = /.{0,1000}\.groups\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string165 = /.{0,1000}\.help\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string166 = /.{0,1000}\.imap\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string167 = /.{0,1000}\.img\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string168 = /.{0,1000}\.kb\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string169 = /.{0,1000}\.lists\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string170 = /.{0,1000}\.live\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string171 = /.{0,1000}\.m\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string172 = /.{0,1000}\.mail\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string173 = /.{0,1000}\.media\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string174 = /.{0,1000}\.mobile\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string175 = /.{0,1000}\.mysql\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string176 = /.{0,1000}\.news\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string177 = /.{0,1000}\.photos\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string178 = /.{0,1000}\.pic\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string179 = /.{0,1000}\.pipename_stager.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string180 = /.{0,1000}\.pop\.123456\..{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string181 = /.{0,1000}\.py\s.{0,1000}\s\-\-teamserver\s.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string182 = /.{0,1000}\.py\s127\.0\.0\.1\s50050\slogtracker\spassword.{0,1000}/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string183 = /.{0,1000}\.py.{0,1000}\s\-\-payload\s.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string184 = /.{0,1000}\.py.{0,1000}\s\-service\-name\s.{0,1000}\s\-hashes\s.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string185 = /.{0,1000}\.resources\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string186 = /.{0,1000}\.search\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string187 = /.{0,1000}\.secure\.123456\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string188 = /.{0,1000}\.sharpgen\s.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string189 = /.{0,1000}\.sites\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string190 = /.{0,1000}\.smtp\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string191 = /.{0,1000}\.ssl\.123456\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string192 = /.{0,1000}\.stage\.123456\..{0,1000}/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string193 = /.{0,1000}\.stage\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string194 = /.{0,1000}\.static\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string195 = /.{0,1000}\.status\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string196 = /.{0,1000}\.store\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string197 = /.{0,1000}\.support\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string198 = /.{0,1000}\.videos\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string199 = /.{0,1000}\.vpn\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string200 = /.{0,1000}\.webmail\.123456\..{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string201 = /.{0,1000}\.wiki\.123456\..{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string202 = /.{0,1000}\/\.aggressor\.prop.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string203 = /.{0,1000}\/\.ssh\/RAI\.pub.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string204 = /.{0,1000}\/\/StaticSyscallsDump\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string205 = /.{0,1000}\/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string206 = /.{0,1000}\/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string207 = /.{0,1000}\/AceLdr\.cna.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string208 = /.{0,1000}\/adcs_enum\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string209 = /.{0,1000}\/adcs_request\/adcs_request\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string210 = /.{0,1000}\/adcs_request\/CertCli\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string211 = /.{0,1000}\/adcs_request\/certenroll\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string212 = /.{0,1000}\/adcs_request\/CertPol\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string213 = /.{0,1000}\/AddUser\-Bof\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string214 = /.{0,1000}\/AddUser\-Bof\/.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string215 = /.{0,1000}\/AggressiveClean\.cna.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string216 = /.{0,1000}\/aggressor\/.{0,1000}\.java.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string217 = /.{0,1000}\/aggressor\-powerview.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string218 = /.{0,1000}\/AggressorScripts.{0,1000}/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string219 = /.{0,1000}\/AggressorScripts.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string220 = /.{0,1000}\/AggressorScripts.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string221 = /.{0,1000}\/agscript\s.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string222 = /.{0,1000}\/agscript\s.{0,1000}/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string223 = /.{0,1000}\/Alaris\.sln.{0,1000}/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string224 = /.{0,1000}\/ANGRYPUPPY\.cna.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string225 = /.{0,1000}\/anthemtotheego\/CredBandit.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string226 = /.{0,1000}\/artifactor\.py.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string227 = /.{0,1000}\/ase_docker\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string228 = /.{0,1000}\/asprox\.profile.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string229 = /.{0,1000}\/asprox\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string230 = /.{0,1000}\/ASRenum\.cpp.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string231 = /.{0,1000}\/ASRenum\.cs.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string232 = /.{0,1000}\/ASRenum\-BOF.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string233 = /.{0,1000}\/assets\/bin2uuids_file\.py.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string234 = /.{0,1000}\/AttackServers\/.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string235 = /.{0,1000}\/auth\/cc2_auth\..{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string236 = /.{0,1000}\/awesome\-pentest.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string237 = /.{0,1000}\/backoff\.profile.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string238 = /.{0,1000}\/backstab_src\/.{0,1000}/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string239 = /.{0,1000}\/BackupPrivSam\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string240 = /.{0,1000}\/bazarloader\.profile.{0,1000}/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string241 = /.{0,1000}\/beacon\.h/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string242 = /.{0,1000}\/beacon_compatibility.{0,1000}/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string243 = /.{0,1000}\/beacon_compatibility\..{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string244 = /.{0,1000}\/beacon_funcs\/.{0,1000}/ nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string245 = /.{0,1000}\/beacon_health_check\/.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string246 = /.{0,1000}\/beacon_http\/.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string247 = /.{0,1000}\/beacon_notify\.cna.{0,1000}/ nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string248 = /.{0,1000}\/beaconhealth\.cna.{0,1000}/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string249 = /.{0,1000}\/beacon\-injection\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike beacon object files
        // Reference: https://github.com/realoriginal/beacon-object-file
        $string250 = /.{0,1000}\/beacon\-object\-file.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string251 = /.{0,1000}\/BeaconTool\.java.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string252 = /.{0,1000}\/bin\/AceLdr.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string253 = /.{0,1000}\/bin\/Sleeper\.o.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string254 = /.{0,1000}\/bluscreenofjeff\/.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string255 = /.{0,1000}\/bof\.h/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string256 = /.{0,1000}\/BOF\.NET\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string257 = /.{0,1000}\/bof\.nim/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string258 = /.{0,1000}\/bof\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string259 = /.{0,1000}\/bof\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string260 = /.{0,1000}\/bof\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string261 = /.{0,1000}\/bof\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string262 = /.{0,1000}\/bof\/bof\.c/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string263 = /.{0,1000}\/bof\/bof\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string264 = /.{0,1000}\/bof\/IABOF.{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string265 = /.{0,1000}\/bof\/IAStart\.asm.{0,1000}/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string266 = /.{0,1000}\/BOF\-Builder.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string267 = /.{0,1000}\/bof\-collection\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string268 = /.{0,1000}\/BOFNETExamples\/.{0,1000}/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string269 = /.{0,1000}\/BOF\-RegSave.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string270 = /.{0,1000}\/BofRunner\.cs.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string271 = /.{0,1000}\/BOFs\.git.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string272 = /.{0,1000}\/bof\-vs\-template\/.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string273 = /.{0,1000}\/bof\-vs\-template\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string274 = /.{0,1000}\/boku7\/spawn.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string275 = /.{0,1000}\/boku7\/whereami\/.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string276 = /.{0,1000}\/BokuLoader\.c.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string277 = /.{0,1000}\/BokuLoader\.h.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string278 = /.{0,1000}\/BokuLoader\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string279 = /.{0,1000}\/BooExecutor\.cs.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string280 = /.{0,1000}\/bq1iFEP2\/assert\/dll\/.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string281 = /.{0,1000}\/bq1iFEP2\/assert\/exe\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string282 = /.{0,1000}\/breg\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string283 = /.{0,1000}\/breg\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string284 = /.{0,1000}\/build\/encrypted_shellcode.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string285 = /.{0,1000}\/build\/formatted_shellcode.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string286 = /.{0,1000}\/build\/shellcode.{0,1000}/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string287 = /.{0,1000}\/BuildBOFs\/.{0,1000}/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string288 = /.{0,1000}\/burpee\.py.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string289 = /.{0,1000}\/BUYTHEAPTDETECTORNOW.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string290 = /.{0,1000}\/BypassAV\/.{0,1000}/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string291 = /.{0,1000}\/bypassAV\-1\/.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string292 = /.{0,1000}\/C2concealer.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string293 = /.{0,1000}\/c2profile\..{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string294 = /.{0,1000}\/c2profile\.go.{0,1000}/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string295 = /.{0,1000}\/C2script\/.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string296 = /.{0,1000}\/cc2_frp\..{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string297 = /.{0,1000}\/client\/bof\/.{0,1000}\.asm.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string298 = /.{0,1000}\/clipboardinject\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string299 = /.{0,1000}\/clipboardinject\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string300 = /.{0,1000}\/clipmon\/clipmon\.sln.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string301 = /.{0,1000}\/clipmon\/dll\/.{0,1000}/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string302 = /.{0,1000}\/cna\/pipetest\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string303 = /.{0,1000}\/cobaltclip\.c.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string304 = /.{0,1000}\/cobaltclip\.o.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string305 = /.{0,1000}\/Cobalt\-Clip\/.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string306 = /.{0,1000}\/cobaltstrike.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string307 = /.{0,1000}\/cobalt\-strike.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string308 = /.{0,1000}\/CoffeeLdr\.c.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string309 = /.{0,1000}\/CoffeeLdr\/.{0,1000}/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string310 = /.{0,1000}\/COFFLoader.{0,1000}/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string311 = /.{0,1000}\/COFFLoader2\/.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string312 = /.{0,1000}\/com\/blackh4t\/.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string313 = /.{0,1000}\/comfoo\.profile.{0,1000}/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string314 = /.{0,1000}\/CookieProcessor\.cs.{0,1000}/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string315 = /.{0,1000}\/core\/browser_darwin\.go.{0,1000}/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string316 = /.{0,1000}\/core\/browser_linux\.go.{0,1000}/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string317 = /.{0,1000}\/core\/browser_windows\.go.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string318 = /.{0,1000}\/Cracked5pider\/.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string319 = /.{0,1000}\/credBandit\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string320 = /.{0,1000}\/CredEnum\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string321 = /.{0,1000}\/CredEnum\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string322 = /.{0,1000}\/CredEnum\.h.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string323 = /.{0,1000}\/CredPrompt\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string324 = /.{0,1000}\/CredPrompt\/credprompt\.c.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string325 = /.{0,1000}\/CrossC2\..{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string326 = /.{0,1000}\/CrossC2\/.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string327 = /.{0,1000}\/CrossC2Kit.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string328 = /.{0,1000}\/CrossC2Kit\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string329 = /.{0,1000}\/CrossNet\-Beta\/.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string330 = /.{0,1000}\/crypt0p3g\/.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string331 = /.{0,1000}\/cs2modrewrite\/.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string332 = /.{0,1000}\/CS\-BOFs\/.{0,1000}/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string333 = /.{0,1000}\/CSharpWinRM.{0,1000}/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string334 = /.{0,1000}\/C\-\-Shellcode.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string335 = /.{0,1000}\/CS\-Loader\.go.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string336 = /.{0,1000}\/CS\-Loader\/.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string337 = /.{0,1000}\/csOnvps\/.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string338 = /.{0,1000}\/csOnvps\/.{0,1000}/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string339 = /.{0,1000}\/cs\-rdll\-ipc\-example\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string340 = /.{0,1000}\/CS\-Remote\-OPs\-BOF.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string341 = /.{0,1000}\/cs\-token\-vault\/.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string342 = /.{0,1000}\/curl\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string343 = /.{0,1000}\/curl\.x64\.o/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string344 = /.{0,1000}\/curl\.x86\.o/ nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string345 = /.{0,1000}\/custom_payload_generator\/.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string346 = /.{0,1000}\/CWoNaJLBo\/VTNeWw11212\/.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string347 = /.{0,1000}\/CWoNaJLBo\/VTNeWw11213\/.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string348 = /.{0,1000}\/DCOM\sLateral\sMovement\/.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string349 = /.{0,1000}\/defender\-exclusions\/.{0,1000}defender.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string350 = /.{0,1000}\/defender\-exclusions\/.{0,1000}exclusion.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string351 = /.{0,1000}\/DelegationBOF\/.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string352 = /.{0,1000}\/demo_bof\.c.{0,1000}/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string353 = /.{0,1000}\/Dent\/.{0,1000}\/Loader\/Loader\.go.{0,1000}/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string354 = /.{0,1000}\/Dent\/Dent\.go.{0,1000}/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string355 = /.{0,1000}\/Dent\/Loader.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string356 = /.{0,1000}\/DesertFox\/archive\/.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string357 = /.{0,1000}\/detect\-hooks\.c.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string358 = /.{0,1000}\/detect\-hooks\.cna.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string359 = /.{0,1000}\/detect\-hooks\.h.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string360 = /.{0,1000}\/Detect\-Hooks\/.{0,1000}/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string361 = /.{0,1000}\/dist\/fw_walk\..{0,1000}/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string362 = /.{0,1000}\/DLL\-Hijack.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string363 = /.{0,1000}\/Doge\-Loader\/.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string364 = /.{0,1000}\/DotNet\/SigFlip.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string365 = /.{0,1000}\/dukes_apt29\.profile.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string366 = /.{0,1000}\/dump_lsass\..{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string367 = /.{0,1000}\/dumpert\.c.{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string368 = /.{0,1000}\/Dumpert\/.{0,1000}/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string369 = /.{0,1000}\/dumpXor\.exe.{0,1000}/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string370 = /.{0,1000}\/dumpXor\/dumpXor.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string371 = /.{0,1000}\/ElevateKit\/elevate\..{0,1000}/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string372 = /.{0,1000}\/ELFLoader\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string373 = /.{0,1000}\/emotet\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string374 = /.{0,1000}\/enableuser\/enableuser\.x64\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string375 = /.{0,1000}\/enableuser\/enableuser\.x86\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string376 = /.{0,1000}\/EnumCLR\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string377 = /.{0,1000}\/enumerate\.cna.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string378 = /.{0,1000}\/Erebus\/.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string379 = /.{0,1000}\/Erebus\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string380 = /.{0,1000}\/Erebus\-email\..{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string381 = /.{0,1000}\/etumbot\.profile.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string382 = /.{0,1000}\/etw\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string383 = /.{0,1000}\/etw\.x64\..{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string384 = /.{0,1000}\/etw\.x86\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string385 = /.{0,1000}\/EventViewerUAC\/.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string386 = /.{0,1000}\/EventViewerUAC\/.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string387 = /.{0,1000}\/evil\.cpp.{0,1000}/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string388 = /.{0,1000}\/exports_function_hid\.txt.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string389 = /.{0,1000}\/fiesta\.profile.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string390 = /.{0,1000}\/fiesta2\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string391 = /.{0,1000}\/final_shellcode_size\.txt.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string392 = /.{0,1000}\/FindModule\.c.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string393 = /.{0,1000}\/FindObjects\.cna.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string394 = /.{0,1000}\/Fodetect\-hooksx64.{0,1000}/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string395 = /.{0,1000}\/FuckThatPacker.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string396 = /.{0,1000}\/G0ldenGunSec\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string397 = /.{0,1000}\/gandcrab\.profile.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string398 = /.{0,1000}\/geacon\/.{0,1000}beacon.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string399 = /.{0,1000}\/geacon_pro.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string400 = /.{0,1000}\/get\-loggedon\/.{0,1000}\.c.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string401 = /.{0,1000}\/get\-system\/getsystem\.c.{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string402 = /.{0,1000}\/GetWebDAVStatus_BOF\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string403 = /.{0,1000}\/globeimposter\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string404 = /.{0,1000}\/guervild\/BOFs.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string405 = /.{0,1000}\/hancitor\.profile.{0,1000}/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com/EspressoCake/HandleKatz_BOF
        $string406 = /.{0,1000}\/HandleKatz_BOF.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string407 = /.{0,1000}\/HaryyUser\.exe.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string408 = /.{0,1000}\/havex\.profile.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string409 = /.{0,1000}\/HiddenDesktop\.git.{0,1000}/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string410 = /.{0,1000}\/hollow\.x64\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string411 = /.{0,1000}\/hooks\/spoof\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string412 = /.{0,1000}\/hostenum\.py.{0,1000}/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string413 = /.{0,1000}\/HouQing\/.{0,1000}\/Loader\.go/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string414 = /.{0,1000}\/injectAmsiBypass\/.{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string415 = /.{0,1000}\/inject\-assembly\/.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string416 = /.{0,1000}\/injectEtw\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string417 = /.{0,1000}\/Injection\/clipboard\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string418 = /.{0,1000}\/Injection\/conhost\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string419 = /.{0,1000}\/Injection\/createremotethread\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string420 = /.{0,1000}\/Injection\/ctray\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string421 = /.{0,1000}\/Injection\/dde\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string422 = /.{0,1000}\/Injection\/Injection\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string423 = /.{0,1000}\/Injection\/kernelcallbacktable.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string424 = /.{0,1000}\/Injection\/ntcreatethread.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string425 = /.{0,1000}\/Injection\/ntcreatethread\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string426 = /.{0,1000}\/Injection\/ntqueueapcthread.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string427 = /.{0,1000}\/Injection\/setthreadcontext.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string428 = /.{0,1000}\/Injection\/svcctrl\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string429 = /.{0,1000}\/Injection\/tooltip\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string430 = /.{0,1000}\/Injection\/uxsubclassinfo.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string431 = /.{0,1000}\/InlineWhispers.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string432 = /.{0,1000}\/Internals\/Coff\.cs.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string433 = /.{0,1000}\/Inveigh\.txt.{0,1000}/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string434 = /.{0,1000}\/Invoke\-Bof\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string435 = /.{0,1000}\/Invoke\-HostEnum\.ps1.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string436 = /.{0,1000}\/jaff\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string437 = /.{0,1000}\/jasperloader\.profile.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string438 = /.{0,1000}\/K8_CS_.{0,1000}_.{0,1000}\.rar.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string439 = /.{0,1000}\/k8gege\/.{0,1000}/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string440 = /.{0,1000}\/k8gege\/scrun\/.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string441 = /.{0,1000}\/k8gege520.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string442 = /.{0,1000}\/kdstab\..{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string443 = /.{0,1000}\/KDStab\..{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string444 = /.{0,1000}\/KDStab\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string445 = /.{0,1000}\/Kerbeus\-BOF\.git.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string446 = /.{0,1000}\/Kerbeus\-BOF\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string447 = /.{0,1000}\/KernelMii\.c.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string448 = /.{0,1000}\/Koh\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string449 = /.{0,1000}\/kronos\.profile.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string450 = /.{0,1000}\/Ladon\.go.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string451 = /.{0,1000}\/Ladon\.ps1.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string452 = /.{0,1000}\/Ladon\.py.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string453 = /.{0,1000}\/Ladon\/Ladon\..{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string454 = /.{0,1000}\/Ladon\/obj\/x86.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string455 = /.{0,1000}\/LadonGo\/.{0,1000}/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string456 = /.{0,1000}\/LetMeOutSharp\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string457 = /.{0,1000}\/lib\/ipLookupHelper\.py.{0,1000}/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string458 = /.{0,1000}\/loader\/x64\/Release\/loader\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string459 = /.{0,1000}\/loadercrypt_.{0,1000}\.php.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string460 = /.{0,1000}\/logs\/.{0,1000}\/becon_.{0,1000}\.log/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string461 = /.{0,1000}\/logs\/beacon_log.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string462 = /.{0,1000}\/lpBunny\/bof\-registry.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string463 = /.{0,1000}\/lsass\/beacon\.h.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string464 = /.{0,1000}\/magnitude\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string465 = /.{0,1000}\/malleable\-c2.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string466 = /.{0,1000}\/manjusaka\/plugins.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string467 = /.{0,1000}\/MemReader_BoF\/.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string468 = /.{0,1000}\/mimipenguin\.c.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string469 = /.{0,1000}\/mimipenguin\/.{0,1000}/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string470 = /.{0,1000}\/minimal_elf\.h.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string471 = /.{0,1000}\/Misc\/donut\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string472 = /.{0,1000}\/Mockingjay_BOF\.git.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string473 = /.{0,1000}\/Modules\/Exitservice\/uinit\.exe.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string474 = /.{0,1000}\/Mr\-Un1k0d3r\/.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string475 = /.{0,1000}\/Native\/SigFlip\/.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string476 = /.{0,1000}\/nccgroup\/nccfsas\/.{0,1000}/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string477 = /.{0,1000}\/Needle_Sift_BOF\/.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string478 = /.{0,1000}\/nettitude\/RunOF\/.{0,1000}/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string479 = /.{0,1000}\/NetUser\.cpp.{0,1000}/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string480 = /.{0,1000}\/NetUser\.exe.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string481 = /.{0,1000}\/netuserenum\/.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string482 = /.{0,1000}\/Network\/PortScan\/.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string483 = /.{0,1000}\/Newtonsoft\.Json\.dll.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string484 = /.{0,1000}\/No\-Consolation\.git.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string485 = /.{0,1000}\/ntlmrelayx\/.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string486 = /.{0,1000}\/oab\-parse\/mspack\..{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string487 = /.{0,1000}\/OG\-Sadpanda\/.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string488 = /.{0,1000}\/On_Demand_C2\/.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string489 = /.{0,1000}\/opt\/implant\/.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string490 = /.{0,1000}\/opt\/rai\/.{0,1000}/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string491 = /.{0,1000}\/optiv\/Dent\/.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string492 = /.{0,1000}\/oscp\.profile.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string493 = /.{0,1000}\/outflanknl\/.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string494 = /.{0,1000}\/output\/payloads\/.{0,1000}/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string495 = /.{0,1000}\/p292\/Phant0m.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string496 = /.{0,1000}\/package\/portscan\/.{0,1000}\.go/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string497 = /.{0,1000}\/password\/mimipenguin\/.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string498 = /.{0,1000}\/payload_scripts.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string499 = /.{0,1000}\/payload_scripts\/artifact.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string500 = /.{0,1000}\/PersistBOF\/.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string501 = /.{0,1000}\/PhishingServer\/.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string502 = /.{0,1000}\/pitty_tiger\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string503 = /.{0,1000}\/popCalc\.bin.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string504 = /.{0,1000}\/PortBender\/.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string505 = /.{0,1000}\/portscan\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string506 = /.{0,1000}\/POSeidon\.profile.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string507 = /.{0,1000}\/PowerView\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string508 = /.{0,1000}\/PowerView3\.cna.{0,1000}/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string509 = /.{0,1000}\/PPEnum\/.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string510 = /.{0,1000}\/ppldump\..{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string511 = /.{0,1000}\/PPLDump_BOF\/.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string512 = /.{0,1000}\/PrintMonitorDll\..{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string513 = /.{0,1000}\/PrintMonitorDll\/.{0,1000}/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string514 = /.{0,1000}\/PrintSpoofer\/.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string515 = /.{0,1000}\/PrivilegeEscalation\/.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string516 = /.{0,1000}\/proberbyte\.go.{0,1000}/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string517 = /.{0,1000}\/Proxy_Def_File_Generator\.cna.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string518 = /.{0,1000}\/putter\.profile.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string519 = /.{0,1000}\/pyasn1\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string520 = /.{0,1000}\/pycobalt\-.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string521 = /.{0,1000}\/pycobalt\/.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string522 = /.{0,1000}\/pystinger\.zip.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string523 = /.{0,1000}\/qakbot\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string524 = /.{0,1000}\/quantloader\.profile.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string525 = /.{0,1000}\/RAI\.git.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string526 = /.{0,1000}\/ramnit\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string527 = /.{0,1000}\/ratankba\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string528 = /.{0,1000}\/raw_shellcode_size\.txt.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string529 = /.{0,1000}\/RC4Payload32\.txt.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string530 = /.{0,1000}\/RCStep\/CSSG\/.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string531 = /.{0,1000}\/readfile_bof\..{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string532 = /.{0,1000}\/Readfile_BoF\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string533 = /.{0,1000}\/red\-team\-scripts.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string534 = /.{0,1000}\/RedWarden\.git.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string535 = /.{0,1000}\/RegistryPersistence\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string536 = /.{0,1000}\/Registry\-Recon\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string537 = /.{0,1000}\/Remote\/adcs_request\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string538 = /.{0,1000}\/Remote\/office_tokens\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string539 = /.{0,1000}\/Remote\/procdump\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string540 = /.{0,1000}\/Remote\/ProcessDestroy\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string541 = /.{0,1000}\/Remote\/ProcessListHandles\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string542 = /.{0,1000}\/Remote\/schtaskscreate\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string543 = /.{0,1000}\/Remote\/schtasksrun\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string544 = /.{0,1000}\/Remote\/setuserpass\// nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string545 = /.{0,1000}\/Remote\/setuserpass\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string546 = /.{0,1000}\/Remote\/unexpireuser\/.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string547 = /.{0,1000}\/remotereg\.c.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string548 = /.{0,1000}\/remotereg\.o.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string549 = /.{0,1000}\/RunOF\/RunOF\/.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string550 = /.{0,1000}\/runshellcode\..{0,1000}/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string551 = /.{0,1000}\/S3cur3Th1sSh1t\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string552 = /.{0,1000}\/saefko\.profile.{0,1000}/ nocase ascii wide
        // Description: A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.
        // Reference: https://github.com/optiv/Dent
        $string553 = /.{0,1000}\/ScareCrow\s\-I\s.{0,1000}/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string554 = /.{0,1000}\/ScRunHex\.py.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string555 = /.{0,1000}\/searchsploit.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string556 = /.{0,1000}\/Seatbelt\.txt.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string557 = /.{0,1000}\/secinject\.c.{0,1000}/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string558 = /.{0,1000}\/self_delete\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string559 = /.{0,1000}\/SeriousSam\.sln.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string560 = /.{0,1000}\/serverscan\/CobaltStrike.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string561 = /.{0,1000}\/serverscan_Air.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string562 = /.{0,1000}\/serverscan_pro.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string563 = /.{0,1000}\/ServerScanForLinux\/.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string564 = /.{0,1000}\/ServerScanForWindows\/.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string565 = /.{0,1000}\/ServerScanForWindows\/PE.{0,1000}/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string566 = /.{0,1000}\/ServiceMove\-BOF\/.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string567 = /.{0,1000}\/Services\/TransitEXE\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string568 = /.{0,1000}\/setuserpass\.x64\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string569 = /.{0,1000}\/setuserpass\.x86\..{0,1000}/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string570 = /.{0,1000}\/SharpCalendar\/.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string571 = /.{0,1000}\/SharpCat\/.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string572 = /.{0,1000}\/SharpCompile\/.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string573 = /.{0,1000}\/sharpcompile_.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string574 = /.{0,1000}\/SharpCradle\/.{0,1000}/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string575 = /.{0,1000}\/SharpSword\/SharpSword.{0,1000}/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string576 = /.{0,1000}\/ShellCode_Loader.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string577 = /.{0,1000}\/shspawnas\/.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string578 = /.{0,1000}\/sigflip\.x64\..{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string579 = /.{0,1000}\/sigflip\.x86\..{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string580 = /.{0,1000}\/SigLoader\.go.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string581 = /.{0,1000}\/SigLoader\/.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string582 = /.{0,1000}\/SilentClean\.exe.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string583 = /.{0,1000}\/SilentClean\/SilentClean\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string584 = /.{0,1000}\/silentdump\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string585 = /.{0,1000}\/silentdump\.h.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string586 = /.{0,1000}\/sleep_python_bridge\/.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string587 = /.{0,1000}\/Sleeper\/Sleeper\.cna.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string588 = /.{0,1000}\/sleepmask\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that spawns a sacrificial process. injects it with shellcode. and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG). BlockDll. and PPID spoofing.
        // Reference: https://github.com/boku7/spawn
        $string589 = /.{0,1000}\/spawn\.git.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string590 = /.{0,1000}\/spoolsystem\/SpoolTrigger\/.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string591 = /.{0,1000}\/Spray\-AD\..{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string592 = /.{0,1000}\/Spray\-AD\/.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string593 = /.{0,1000}\/src\/Sleeper\.cpp.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string594 = /.{0,1000}\/StaticSyscallsAPCSpawn\/.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string595 = /.{0,1000}\/StaticSyscallsInject\/.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string596 = /.{0,1000}\/StayKit\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string597 = /.{0,1000}\/Staykit\/StayKit\..{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string598 = /.{0,1000}\/striker\.py/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string599 = /.{0,1000}\/string_of_paerls\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string600 = /.{0,1000}\/suspendresume\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string601 = /.{0,1000}\/suspendresume\.x86.{0,1000}/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string602 = /.{0,1000}\/SweetPotato_CS.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string603 = /.{0,1000}\/SyscallsInject\/.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string604 = /.{0,1000}\/taidoor\.profile.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string605 = /.{0,1000}\/tcpshell\.py.{0,1000}/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string606 = /.{0,1000}\/test32\.dll.{0,1000}/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string607 = /.{0,1000}\/test64\.dll.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string608 = /.{0,1000}\/tests\/test\-bof\.ps1.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string609 = /.{0,1000}\/tevora\-threat\/PowerView.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string610 = /.{0,1000}\/tgtParse\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string611 = /.{0,1000}\/tgtParse\/tgtParse\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string612 = /.{0,1000}\/ticketConverter\.exe.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string613 = /.{0,1000}\/TikiLoader\/.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string614 = /.{0,1000}\/TikiSpawn\..{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string615 = /.{0,1000}\/TikiSpawn\/.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string616 = /.{0,1000}\/TokenStripBOF.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string617 = /.{0,1000}\/tools\/BeaconTool\/.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string618 = /.{0,1000}\/Tools\/spoolsystem\/.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string619 = /.{0,1000}\/Tools\/Squeak\/Squeak.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string620 = /.{0,1000}\/trick_ryuk\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string621 = /.{0,1000}\/trickbot\.profile.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string622 = /.{0,1000}\/UAC\-SilentClean\/.{0,1000}/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string623 = /.{0,1000}\/unhook\-bof.{0,1000}/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/Cobalt-Strike/unhook-bof
        $string624 = /.{0,1000}\/unhook\-bof.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string625 = /.{0,1000}\/UTWOqVQ132\/.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string626 = /.{0,1000}\/vssenum\/.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string627 = /.{0,1000}\/WdToggle\.c.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string628 = /.{0,1000}\/WdToggle\.h.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string629 = /.{0,1000}\/webshell\/.{0,1000}\.aspx.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string630 = /.{0,1000}\/webshell\/.{0,1000}\.jsp.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string631 = /.{0,1000}\/webshell\/.{0,1000}\.php.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string632 = /.{0,1000}\/wifidump\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string633 = /.{0,1000}\/WindowsVault\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string634 = /.{0,1000}\/WindowsVault\.h.{0,1000}/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string635 = /.{0,1000}\/winrm\.cpp.{0,1000}/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string636 = /.{0,1000}\/winrmdll.{0,1000}/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string637 = /.{0,1000}\/winrm\-reflective\-dll\/.{0,1000}/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string638 = /.{0,1000}\/Winsocky\.git.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string639 = /.{0,1000}\/WMI\sLateral\sMovement\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string640 = /.{0,1000}\/wwlib\/lolbins\/.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string641 = /.{0,1000}\/xen\-mimi\.ps1.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string642 = /.{0,1000}\/xor\/stager\.txt.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string643 = /.{0,1000}\/xor\/xor\.go.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string644 = /.{0,1000}\/xPipe\/.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string645 = /.{0,1000}\/yanghaoi\/_CNA.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string646 = /.{0,1000}\/zerologon\.cna.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string647 = /.{0,1000}\[\'spawnto\'\].{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string648 = /.{0,1000}\\\\GetWebDAVStatus\.exe.{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string649 = /.{0,1000}\\\\pipe\\\\DAV\sRPC\sSERVICE.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string650 = /.{0,1000}\\8e8988b257e9dd2ea44ff03d44d26467b7c9ec16.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string651 = /.{0,1000}\\asreproasting\.c.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string652 = /.{0,1000}\\beacon\.exe.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string653 = /.{0,1000}\\CrossC2\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string654 = /.{0,1000}\\CROSSNET\\CROSSNET\\.{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string655 = /.{0,1000}\\dumpert\..{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string656 = /.{0,1000}\\Dumpert\\.{0,1000}/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string657 = /.{0,1000}\\DumpShellcode.{0,1000}/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string658 = /.{0,1000}\\dumpXor\.exe.{0,1000}/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string659 = /.{0,1000}\\dumpXor\\x64\\.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string660 = /.{0,1000}\\ELF\\portscan.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string661 = /.{0,1000}\\ELF\\serverscan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string662 = /.{0,1000}\\evil\.dll.{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string663 = /.{0,1000}\\GetWebDAVStatus\\/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string664 = /.{0,1000}\\GetWebDAVStatus_x64.{0,1000}/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string665 = /.{0,1000}\\HackBrowserData.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string666 = /.{0,1000}\\HiddenDesktop\\.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string667 = /.{0,1000}\\HostEnum\.ps1.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string668 = /.{0,1000}\\kdstab\.exe.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string669 = /.{0,1000}\\kerberoasting\.c.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string670 = /.{0,1000}\\Kerbeus\-BOF\\.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string671 = /.{0,1000}\\Koh\.exe.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string672 = /.{0,1000}\\Koh\.pdb.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string673 = /.{0,1000}\\Koh\\Koh\..{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string674 = /.{0,1000}\\Ladon\.exe.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string675 = /.{0,1000}\\Ladon\.ps1.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string676 = /.{0,1000}\\LogonScreen\.exe.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string677 = /.{0,1000}\\lsass\.dmp.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string678 = /.{0,1000}\\Mockingjay_BOF\..{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string679 = /.{0,1000}\\No\-Consolation\\source\\.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string680 = /.{0,1000}\\portbender\..{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string681 = /.{0,1000}\\PowerView\.cna.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string682 = /.{0,1000}\\PowerView\.exe.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string683 = /.{0,1000}\\PowerView\.ps1.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string684 = /.{0,1000}\\PowerView3\..{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string685 = /.{0,1000}\\RunBOF\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string686 = /.{0,1000}\\RunOF\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string687 = /.{0,1000}\\RunOF\\bin\\.{0,1000}/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string688 = /.{0,1000}\\samantha\.txt/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string689 = /.{0,1000}\\SharpMove\.exe.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string690 = /.{0,1000}\\SigFlip\.exe.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string691 = /.{0,1000}\\SilentClean\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string692 = /.{0,1000}\\StayKit\.cna.{0,1000}/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string693 = /.{0,1000}\\systemic\.txt/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string694 = /.{0,1000}\\TASKSHELL\.EXE.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string695 = /.{0,1000}\\TikiCompiler\.txt.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string696 = /.{0,1000}\\TikiService\.exe.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string697 = /.{0,1000}\\TikiSpawn\..{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string698 = /.{0,1000}\\tikispawn\.xml.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string699 = /.{0,1000}\\TikiTorch\\Aggressor.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string700 = /.{0,1000}_cobaltstrike.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string701 = /.{0,1000}_find_sharpgen_dll.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string702 = /.{0,1000}_pycobalt_.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string703 = /.{0,1000}_tcp_cc2\(.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string704 = /.{0,1000}_udp_cc2\(.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string705 = /.{0,1000}\<CoffeLdr\.h\>.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string706 = /.{0,1000}0xthirteen\/MoveKit.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string707 = /.{0,1000}0xthirteen\/StayKit.{0,1000}/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string708 = /.{0,1000}0xthirteen\/StayKit.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string709 = /.{0,1000}4d5350c8\-7f8c\-47cf\-8cde\-c752018af17e.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string710 = /.{0,1000}516280565958.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string711 = /.{0,1000}516280565959.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string712 = /.{0,1000}5a40f11a99d0db4a0b06ab5b95c7da4b1c05b55a99c7c443021bff02c2cf93145c53ff5b.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string713 = /.{0,1000}5e98194a01c6b48fa582a6a9fcbb92d6.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string714 = /.{0,1000}5e98194a01c6b48fa582a6a9fcbb92d6.{0,1000}/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string715 = /.{0,1000}6e7645c4\-32c5\-4fe3\-aabf\-e94c2f4370e7.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string716 = /.{0,1000}713724C3\-2367\-49FA\-B03F\-AB4B336FB405.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string717 = /.{0,1000}732211ae\-4891\-40d3\-b2b6\-85ebd6f5ffff.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string718 = /.{0,1000}7CFC52\.dll.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string719 = /.{0,1000}7CFC52CD3F\.dll.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string720 = /.{0,1000}913d774e5cf0bfad4adfa900997f7a1a.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string721 = /.{0,1000}913d774e5cf0bfad4adfa900997f7a1a.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string722 = /.{0,1000}AceLdr\..{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string723 = /.{0,1000}AceLdr\.zip.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string724 = /.{0,1000}adcs_enum\..{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string725 = /.{0,1000}adcs_enum_com\..{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string726 = /.{0,1000}adcs_enum_com2\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string727 = /.{0,1000}AddUser\-Bof\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string728 = /.{0,1000}AddUser\-Bof\.git.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string729 = /.{0,1000}AddUser\-Bof\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string730 = /.{0,1000}AddUser\-Bof\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that Add an admin user
        // Reference: https://github.com/0x3rhy/AddUser-Bof
        $string731 = /.{0,1000}AddUser\-Bof\.x86.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string732 = /.{0,1000}AddUserToDomainGroup\s.{0,1000}Domain\sAdmins.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string733 = /.{0,1000}AddUserToDomainGroup\..{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string734 = /.{0,1000}AddUserToDomainGroup\.cna.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string735 = /.{0,1000}Adminisme\/ServerScan\/.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string736 = /.{0,1000}ag_load_script.{0,1000}/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string737 = /.{0,1000}AggressiveProxy\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string738 = /.{0,1000}aggressor\.beacons.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string739 = /.{0,1000}aggressor\.bshell.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string740 = /.{0,1000}aggressor\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string741 = /.{0,1000}aggressor\.dialog.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string742 = /.{0,1000}aggressor\.println.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string743 = /.{0,1000}aggressor\.py.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string744 = /.{0,1000}Aggressor\/TikiTorch.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string745 = /.{0,1000}Aggressor\-Scripts.{0,1000}/ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string746 = /.{0,1000}aggressor\-scripts.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string747 = /.{0,1000}ajpc500\/BOFs.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string748 = /.{0,1000}Alphabug_CS.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string749 = /.{0,1000}Alphabug_CS.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string750 = /.{0,1000}AlphabugX\/csOnvps.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string751 = /.{0,1000}AlphabugX\/csOnvps.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string752 = /.{0,1000}Already\sSYSTEM.{0,1000}not\selevating.{0,1000}/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string753 = /.{0,1000}ANGRYPUPPY2\.cna.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string754 = /.{0,1000}anthemtotheego\/Detect\-Hooks.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string755 = /.{0,1000}apokryptein\/secinject.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string756 = /.{0,1000}applocker_enum.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string757 = /.{0,1000}applocker\-enumerator.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string758 = /.{0,1000}apt1_virtuallythere\.profile.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string759 = /.{0,1000}arsenal_kit\.cna.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string760 = /.{0,1000}artifact\.cna.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string761 = /.{0,1000}artifact\.cna.{0,1000}/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string762 = /.{0,1000}artifact\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string763 = /.{0,1000}artifact\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string764 = /.{0,1000}artifact\.x86\.dll.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string765 = /.{0,1000}artifact\.x86\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string766 = /.{0,1000}artifact_payload.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string767 = /.{0,1000}artifact_payload.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string768 = /.{0,1000}artifact_stageless.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string769 = /.{0,1000}artifact_stageless.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string770 = /.{0,1000}artifact_stager.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string771 = /.{0,1000}artifact_stager.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string772 = /.{0,1000}artifact32.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string773 = /.{0,1000}artifact32\.dll.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string774 = /.{0,1000}artifact32\.dll.{0,1000}/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string775 = /.{0,1000}artifact32\.exe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string776 = /.{0,1000}artifact32\.exe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string777 = /.{0,1000}artifact32big\.dll.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string778 = /.{0,1000}artifact32big\.exe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string779 = /.{0,1000}artifact32svc\.exe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string780 = /.{0,1000}artifact32svcbig\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string781 = /.{0,1000}artifact64.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string782 = /.{0,1000}artifact64\.dll.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string783 = /.{0,1000}artifact64\.exe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string784 = /.{0,1000}artifact64\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string785 = /.{0,1000}artifact64big\.exe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string786 = /.{0,1000}artifact64big\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string787 = /.{0,1000}artifact64svc\.exe.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string788 = /.{0,1000}artifact64svcbig\.exe.{0,1000}/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string789 = /.{0,1000}artifactbig64\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string790 = /.{0,1000}artifactuac.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string791 = /.{0,1000}asktgs\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF that identifies Attack Surface Reduction (ASR) rules. actions. and exclusion locations
        // Reference: https://github.com/mlcsec/ASRenum-BOF
        $string792 = /.{0,1000}ASRenum\-BOF\..{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string793 = /.{0,1000}asreproasting\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string794 = /.{0,1000}Assemblies\/SharpMove\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOFs
        // Reference: https://github.com/AttackTeamFamily/cobaltstrike-bof-toolset
        $string795 = /.{0,1000}AttackTeamFamily.{0,1000}\-bof\-toolset.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string796 = /.{0,1000}ausecwa\/bof\-registry.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string797 = /.{0,1000}auth\/cc2_ssh\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string798 = /.{0,1000}Backdoor\sLNK.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string799 = /.{0,1000}\-\-backdoor\-all.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string800 = /.{0,1000}backdoorlnkdialog.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string801 = /.{0,1000}backstab\.x64\..{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string802 = /.{0,1000}backstab\.x86\..{0,1000}/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string803 = /.{0,1000}BackupPrivSAM\s\\\\.{0,1000}/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string804 = /.{0,1000}backupprivsam\..{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string805 = /.{0,1000}BadPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string806 = /.{0,1000}bawait_upload.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string807 = /.{0,1000}bawait_upload_raw.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string808 = /.{0,1000}bblockdlls.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string809 = /.{0,1000}bbrowserpivot.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string810 = /.{0,1000}bbrowserpivot.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string811 = /.{0,1000}bbypassuac.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string812 = /.{0,1000}bcc2_setenv.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string813 = /.{0,1000}bcc2_spawn.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string814 = /.{0,1000}bcrossc2_load_dyn.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 Profiles. A collection of profiles used in different projects using Cobalt Strike & Empire.
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string815 = /.{0,1000}BC\-SECURITY.{0,1000}Malleable.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string816 = /.{0,1000}bdcsync.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string817 = /.{0,1000}bdllinject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string818 = /.{0,1000}bdllinject.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string819 = /.{0,1000}bdllload.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string820 = /.{0,1000}bdllload.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string821 = /.{0,1000}bdllspawn.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string822 = /.{0,1000}bdllspawn.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string823 = /.{0,1000}Beacon\sPayload\sGenerator.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string824 = /.{0,1000}beacon\..{0,1000}winsrv\.dll.{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string825 = /.{0,1000}beacon\.CommandBuilder.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string826 = /.{0,1000}beacon\.CommandBuilder.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string827 = /.{0,1000}beacon\.dll.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string828 = /.{0,1000}beacon\.exe.{0,1000}/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string829 = /.{0,1000}beacon\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string830 = /.{0,1000}beacon\.nim.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string831 = /.{0,1000}Beacon\.Object\.File\.zip.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string832 = /.{0,1000}beacon\.x64.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string833 = /.{0,1000}beacon\.x64.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string834 = /.{0,1000}beacon\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string835 = /.{0,1000}beacon\.x86.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string836 = /.{0,1000}beacon\.x86.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string837 = /.{0,1000}beacon_api\.h.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string838 = /.{0,1000}beacon_bottom\s.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string839 = /.{0,1000}Beacon_Com_Struct.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string840 = /.{0,1000}beacon_command_describe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string841 = /.{0,1000}beacon_command_detail.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string842 = /.{0,1000}beacon_command_detail.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string843 = /.{0,1000}beacon_command_register.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string844 = /.{0,1000}beacon_command_register.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string845 = /.{0,1000}beacon_commands.{0,1000}/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string846 = /.{0,1000}beacon_compatibility\.c.{0,1000}/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string847 = /.{0,1000}beacon_compatibility\.h.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string848 = /.{0,1000}beacon_elevator_describe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string849 = /.{0,1000}beacon_elevator_describe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string850 = /.{0,1000}beacon_elevator_register.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string851 = /.{0,1000}beacon_elevator_register.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string852 = /.{0,1000}beacon_elevator_register.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string853 = /.{0,1000}beacon_elevators.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string854 = /.{0,1000}beacon_elevators.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string855 = /.{0,1000}beacon_execute_job.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string856 = /.{0,1000}beacon_exploit_describe.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string857 = /.{0,1000}beacon_exploit_register.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string858 = /.{0,1000}beacon_funcs\.c.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string859 = /.{0,1000}beacon_funcs\.h.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string860 = /.{0,1000}beacon_funcs\.x64\..{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string861 = /.{0,1000}beacon_funcs\.x86\..{0,1000}/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string862 = /.{0,1000}beacon_generate\.py.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string863 = /.{0,1000}Beacon_GETPOST.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string864 = /.{0,1000}beacon_host_script.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string865 = /.{0,1000}beacon_host_script.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string866 = /.{0,1000}beacon_inline_execute.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string867 = /.{0,1000}beacon_inline_execute.{0,1000}/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string868 = /.{0,1000}beacon_inline_execute.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string869 = /.{0,1000}beacon_inline_execute.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string870 = /.{0,1000}beacon_log_clean.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string871 = /.{0,1000}beacon_output_ps\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string872 = /.{0,1000}beacon_print.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string873 = /.{0,1000}BEACON_RDLL_.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string874 = /.{0,1000}beacon_remote_exec_.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string875 = /.{0,1000}beacon_remote_exec_method_describe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string876 = /.{0,1000}beacon_remote_exec_method_register.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string877 = /.{0,1000}beacon_remote_exec_methods.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string878 = /.{0,1000}beacon_remote_exploit.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string879 = /.{0,1000}beacon_remote_exploit_arch.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string880 = /.{0,1000}beacon_remote_exploit_describe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string881 = /.{0,1000}beacon_remote_exploit_register.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string882 = /.{0,1000}beacon_remote_exploits.{0,1000}/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string883 = /.{0,1000}beacon_smb\.exe.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string884 = /.{0,1000}Beacon_Stage_p2_Stuct.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string885 = /.{0,1000}beacon_stage_pipe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string886 = /.{0,1000}beacon_stage_pipe.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string887 = /.{0,1000}Beacon_Stage_Struct_p1.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string888 = /.{0,1000}Beacon_Stage_Struct_p3.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string889 = /.{0,1000}beacon_stage_tcp.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string890 = /.{0,1000}beacon_stage_tcp.{0,1000}/ nocase ascii wide
        // Description: default articfact name generated by cobaltsrike Cobalt Strike is threat emulation software. Execute targeted attacks against modern enterprises with one of the most powerful network attack kits available to penetration testers
        // Reference: https://www.cobaltstrike.com/
        $string891 = /.{0,1000}beacon_test\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string892 = /.{0,1000}beacon_top\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string893 = /.{0,1000}beacon_top_callback.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string894 = /.{0,1000}BeaconApi\.cs.{0,1000}/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string895 = /.{0,1000}beacon\-c2\-go.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string896 = /.{0,1000}BeaconCleanupProcess.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string897 = /.{0,1000}BeaconConsoleWriter\.cs.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string898 = /.{0,1000}BeaconGetSpawnTo.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string899 = /.{0,1000}BeaconGetSpawnTo.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string900 = /.{0,1000}BeaconGetSpawnTo.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string901 = /.{0,1000}beacongrapher\.py.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string902 = /.{0,1000}BeaconInjectProcess.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string903 = /.{0,1000}BeaconInjectProcess.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string904 = /.{0,1000}BeaconInjectTemporaryProcess.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string905 = /.{0,1000}BeaconInjectTemporaryProcess.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string906 = /.{0,1000}BeaconJob\.cs.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string907 = /.{0,1000}BeaconJobWriter\.cs.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string908 = /.{0,1000}beaconlogs\.json.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string909 = /.{0,1000}beaconlogtracker\.py.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string910 = /.{0,1000}BeaconNote\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string911 = /.{0,1000}BeaconNotify\.cna.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string912 = /.{0,1000}BeaconObject\.cs.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string913 = /.{0,1000}BeaconOutputStreamW.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string914 = /.{0,1000}BeaconOutputWriter\.cs.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string915 = /.{0,1000}BeaconPrintf\(.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string916 = /.{0,1000}BeaconPrintf.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string917 = /.{0,1000}BeaconPrintToStreamW.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string918 = /.{0,1000}BeaconSpawnTemporaryProcess.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string919 = /.{0,1000}BeaconSpawnTemporaryProcess.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string920 = /.{0,1000}BeaconTool\s\-.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string921 = /.{0,1000}BeaconTool\/lib\/sleep\.jar.{0,1000}/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string922 = /.{0,1000}BeaconUseToken.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string923 = /.{0,1000}bgetprivs.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string924 = /.{0,1000}bhashdump.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string925 = /.{0,1000}bin\/bof_c\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string926 = /.{0,1000}bin\/bof_nim\.o.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string927 = /.{0,1000}bkerberos_ccache_use.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string928 = /.{0,1000}bkerberos_ticket_purge.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string929 = /.{0,1000}bkerberos_ticket_use.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string930 = /.{0,1000}bkeylogger.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string931 = /.{0,1000}blockdlls\sstart.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string932 = /.{0,1000}blockdlls\sstop.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string933 = /.{0,1000}bloginuser.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string934 = /.{0,1000}blogonpasswords.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string935 = /.{0,1000}BOF\sprototype\sworks\!.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string936 = /.{0,1000}bof.{0,1000}\/CredEnum\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string937 = /.{0,1000}BOF\/.{0,1000}procdump\/.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string938 = /.{0,1000}bof_allocator.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string939 = /.{0,1000}bof_helper\.py.{0,1000}/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string940 = /.{0,1000}bof_net_user\.c.{0,1000}/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string941 = /.{0,1000}bof_net_user\.o.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string942 = /.{0,1000}bof_reuse_memory.{0,1000}/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string943 = /.{0,1000}BOF2shellcode.{0,1000}/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string944 = /.{0,1000}bof2shellcode\.py.{0,1000}/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string945 = /.{0,1000}BOF\-DLL\-Inject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string946 = /.{0,1000}bofentry::bof_entry.{0,1000}/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string947 = /.{0,1000}BOF\-ForeignLsass.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string948 = /.{0,1000}BOF\-IShellWindows\-DCOM\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string949 = /.{0,1000}BofLdapSignCheck.{0,1000}/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string950 = /.{0,1000}bofloader\.bin.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string951 = /.{0,1000}bofnet.{0,1000}SeriousSam\..{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string952 = /.{0,1000}BOFNET\.Bofs.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string953 = /.{0,1000}bofnet\.cna.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string954 = /.{0,1000}BOFNET\.csproj.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string955 = /.{0,1000}BOFNET\.sln.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string956 = /.{0,1000}bofnet_boo\s.{0,1000}\.boo.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string957 = /.{0,1000}bofnet_execute\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string958 = /.{0,1000}bofnet_execute\..{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string959 = /.{0,1000}bofnet_init.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string960 = /.{0,1000}bofnet_job\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string961 = /.{0,1000}bofnet_jobkill.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string962 = /.{0,1000}bofnet_jobs.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string963 = /.{0,1000}bofnet_jobstatus\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string964 = /.{0,1000}bofnet_list.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string965 = /.{0,1000}bofnet_listassembiles.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string966 = /.{0,1000}bofnet_load\s.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string967 = /.{0,1000}bofnet_shutdown.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string968 = /.{0,1000}BOFNET_Tests.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string969 = /.{0,1000}bofportscan\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string970 = /.{0,1000}bof\-quser\s.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string971 = /.{0,1000}bof\-quser\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string972 = /.{0,1000}bof\-rdphijack.{0,1000}/ nocase ascii wide
        // Description: Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File
        // Reference: https://github.com/EncodeGroup/BOF-RegSave
        $string973 = /.{0,1000}bof\-regsave\s.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string974 = /.{0,1000}BofRunnerOutput.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string975 = /.{0,1000}BOFs.{0,1000}\/SyscallsSpawn\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string976 = /.{0,1000}Bofs\/AssemblyLoader.{0,1000}/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string977 = /.{0,1000}bof\-servicemove\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string978 = /.{0,1000}bof\-trustedpath\-uacbypass.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string979 = /.{0,1000}boku_pe_customMZ.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string980 = /.{0,1000}boku_pe_customPE.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string981 = /.{0,1000}boku_pe_dll.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string982 = /.{0,1000}boku_pe_mask_.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string983 = /.{0,1000}boku_pe_MZ_from_C2Profile.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string984 = /.{0,1000}boku_strrep.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string985 = /.{0,1000}boku7\/BokuLoader.{0,1000}/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string986 = /.{0,1000}boku7\/HOLLOW.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string987 = /.{0,1000}BokuLoader\.cna.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string988 = /.{0,1000}BokuLoader\.exe.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string989 = /.{0,1000}BokuLoader\.x64.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string990 = /.{0,1000}BooExecutorImpl\.cs.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string991 = /.{0,1000}bpassthehash.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string992 = /.{0,1000}bpowerpick.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string993 = /.{0,1000}bpsexec_command.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string994 = /.{0,1000}bpsexec_command.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string995 = /.{0,1000}bpsexec_psh.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string996 = /.{0,1000}bpsinject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string997 = /.{0,1000}bpsinject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string998 = /.{0,1000}breg\sadd\s.{0,1000}HK.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string999 = /.{0,1000}breg\sdelete\s.{0,1000}HK.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1000 = /.{0,1000}breg\squery\s.{0,1000}HK.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1001 = /.{0,1000}breg_add_string_value.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1002 = /.{0,1000}bremote_exec.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1003 = /.{0,1000}browser_\#\#.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1004 = /.{0,1000}browserpivot\s.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1005 = /.{0,1000}brun_script_in_mem.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1006 = /.{0,1000}brunasadmin.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1007 = /.{0,1000}bshinject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1008 = /.{0,1000}bshinject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1009 = /.{0,1000}bshspawn.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1010 = /.{0,1000}bsteal_token.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1011 = /.{0,1000}bsteal_token.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1012 = /.{0,1000}build\sSourcePoint\.go.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file that allows you to query and make changes to the Windows Registry
        // Reference: https://github.com/ausecwa/bof-registry
        $string1013 = /.{0,1000}build\/breg\.cna.{0,1000}/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1014 = /.{0,1000}build_c_shellcode.{0,1000}/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1015 = /.{0,1000}BuildBOFs\.exe.{0,1000}/ nocase ascii wide
        // Description: C# .Net 5.0 project to build BOF (Beacon Object Files) in mass
        // Reference: https://github.com/ceramicskate0/BOF-Builder
        $string1016 = /.{0,1000}BuildBOFs\.sln.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1017 = /.{0,1000}bupload_raw.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1018 = /.{0,1000}burp2malleable\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike plugin for quickly generating anti-kill executable files
        // Reference: https://github.com/hack2fun/BypassAV
        $string1019 = /.{0,1000}BypassAV\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1020 = /.{0,1000}bypass\-pipe\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF Files with Nim!
        // Reference: https://github.com/byt3bl33d3r/BOF-Nim
        $string1021 = /.{0,1000}byt3bl33d3r\/BOF\-Nim.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1022 = /.{0,1000}\-c\sBOF\.cpp\s\-o\sBOF\.o.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1023 = /.{0,1000}\-c\sBOF\.cpp\s\-o\sBOF\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1024 = /.{0,1000}C:\\Temp\\poc\.txt.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1025 = /.{0,1000}C:\\Windows\\Temp\\move\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1026 = /.{0,1000}C:\\Windows\\Temp\\moveme\.exe.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1027 = /.{0,1000}C\?\?\/generator\.cpp.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1028 = /.{0,1000}c2lint\s.{0,1000}/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1029 = /.{0,1000}C2ListenerPort.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1030 = /.{0,1000}\-c2\-randomizer\.py.{0,1000}/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1031 = /.{0,1000}C2ReverseClint.{0,1000}/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1032 = /.{0,1000}C2ReverseProxy.{0,1000}/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1033 = /.{0,1000}C2ReverseServer.{0,1000}/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1034 = /.{0,1000}C2script\/proxy\..{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1035 = /.{0,1000}\'c2server\'.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1036 = /.{0,1000}CACTUSTORCH\.cna.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1037 = /.{0,1000}CACTUSTORCH\.cs.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1038 = /.{0,1000}CACTUSTORCH\.hta.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1039 = /.{0,1000}CACTUSTORCH\.js.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1040 = /.{0,1000}CACTUSTORCH\.vba.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1041 = /.{0,1000}CACTUSTORCH\.vbe.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1042 = /.{0,1000}CACTUSTORCH\.vbs.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1043 = /.{0,1000}CALLBACK_HASHDUMP.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1044 = /.{0,1000}CALLBACK_KEYSTROKES.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1045 = /.{0,1000}CALLBACK_NETVIEW.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1046 = /.{0,1000}CALLBACK_PORTSCAN.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1047 = /.{0,1000}CALLBACK_TOKEN_STOLEN.{0,1000}/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1048 = /.{0,1000}CallBackDump.{0,1000}dumpXor.{0,1000}/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1049 = /.{0,1000}CallbackDump\.exe.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1050 = /.{0,1000}careCrow.{0,1000}_linux_amd64.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1051 = /.{0,1000}cat\s.{0,1000}\.bin\s\|\sbase64\s\-w\s0\s\>\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1052 = /.{0,1000}cc2_keystrokes_.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1053 = /.{0,1000}cc2_mimipenguin\..{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1054 = /.{0,1000}cc2_portscan_.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1055 = /.{0,1000}cc2_rebind_.{0,1000}_get_recv.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1056 = /.{0,1000}cc2_rebind_.{0,1000}_get_send.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1057 = /.{0,1000}cc2_rebind_.{0,1000}_post_recv.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1058 = /.{0,1000}cc2_rebind_.{0,1000}_post_send.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1059 = /.{0,1000}cc2_udp_server.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1060 = /.{0,1000}cc2FilesColor\..{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1061 = /.{0,1000}cc2ProcessColor\..{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1062 = /.{0,1000}CCob\/BOF\.NET.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1063 = /.{0,1000}cd\s\.\/whereami\/.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1064 = /.{0,1000}ChatLadon\.exe.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1065 = /.{0,1000}ChatLadon\.rar.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1066 = /.{0,1000}check_and_write_IAT_Hook.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1067 = /.{0,1000}check_function\sntdll\.dll\sEtwEventWrite.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1068 = /.{0,1000}checkIfHiddenAPICall.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1069 = /.{0,1000}chromeKey\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1070 = /.{0,1000}chromeKey\.x86.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1071 = /.{0,1000}chromiumkeydump.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1072 = /.{0,1000}cHux014r17SG3v4gPUrZ0BZjDabMTY2eWDj1tuYdREBg.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1073 = /.{0,1000}clipboardinject\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1074 = /.{0,1000}clipboardinject\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1075 = /.{0,1000}clipboardinject\.x86.{0,1000}/ nocase ascii wide
        // Description: CLIPBRDWNDCLASS process injection technique(BOF) - execute beacon shellcode in callback
        // Reference: https://github.com/BronzeTicket/ClipboardWindow-Inject
        $string1076 = /.{0,1000}ClipboardWindow\-Inject.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1077 = /.{0,1000}clipmon\.sln.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1078 = /.{0,1000}Cobalt\sStrike.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1079 = /.{0,1000}cobaltclip\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1080 = /.{0,1000}cobaltclip\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1081 = /.{0,1000}cobaltstrike\s.{0,1000}/ nocase ascii wide
        // Description: cobaltstrike binary for windows - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network. While penetration tests focus on unpatched vulnerabilities and misconfigurations. these assessments benefit security operations and incident response.
        // Reference: https://www.cobaltstrike.com/
        $string1082 = /.{0,1000}cobaltstrike.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1083 = /.{0,1000}cobaltstrike\-.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1084 = /.{0,1000}cobalt\-strike.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1085 = /.{0,1000}\-cobaltstrike.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1086 = /.{0,1000}cobaltstrike\..{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1087 = /.{0,1000}cobaltstrike\.store.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1088 = /.{0,1000}cobaltstrike\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1089 = /.{0,1000}Cobalt\-Strike\/bof_template.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1090 = /.{0,1000}cobaltstrike_.{0,1000}/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1091 = /.{0,1000}CodeLoad\(shellcode\).{0,1000}/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1092 = /.{0,1000}coff_definitions\.h.{0,1000}/ nocase ascii wide
        // Description: Load and execute COFF files and Cobalt Strike BOFs in-memory
        // Reference: https://github.com/Yaxser/COFFLoader2
        $string1093 = /.{0,1000}COFF_Loader\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1094 = /.{0,1000}COFF_PREP_BEACON.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1095 = /.{0,1000}CoffeeLdr.{0,1000}\sgo\s.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1096 = /.{0,1000}CoffeeLdr\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1097 = /.{0,1000}CoffeeLdr\.x86\.exe.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File Loader
        // Reference: https://github.com/Cracked5pider/CoffeeLdr
        $string1098 = /.{0,1000}COFFELDR_COFFELDR_H.{0,1000}/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1099 = /.{0,1000}COFFLoader\..{0,1000}/ nocase ascii wide
        // Description: This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it
        // Reference: https://github.com/trustedsec/COFFLoader
        $string1100 = /.{0,1000}COFFLoader64\.exe.{0,1000}/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1101 = /.{0,1000}com_exec_go\(.{0,1000}/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1102 = /.{0,1000}com\-exec\.cna.{0,1000}/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1103 = /.{0,1000}common\.ReflectiveDLL.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string1104 = /.{0,1000}common\.ReflectiveDLL.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1105 = /.{0,1000}comnap_\#\#.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1106 = /.{0,1000}comnode_\#\#.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1107 = /.{0,1000}connormcgarr\/tgtdelegation.{0,1000}/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1108 = /.{0,1000}cookie_graber_x64\.o.{0,1000}/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1109 = /.{0,1000}cookie\-graber\.c.{0,1000}/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1110 = /.{0,1000}cookie\-graber_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1111 = /.{0,1000}Cookie\-Graber\-BOF.{0,1000}/ nocase ascii wide
        // Description: C or BOF file to extract WebKit master key to decrypt user cookie. The C code can be used to compile an executable or a bof script for Cobalt Strike.
        // Reference: https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF
        $string1112 = /.{0,1000}CookieProcessor\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1113 = /.{0,1000}covid19_koadic\.profile.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1114 = /.{0,1000}crawlLdrDllList.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1115 = /.{0,1000}credBandit\s.{0,1000}\soutput.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1116 = /.{0,1000}credBandit\..{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1117 = /.{0,1000}credBanditx64.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string1118 = /.{0,1000}CredPrompt\/CredPrompt\.cna.{0,1000}/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1119 = /.{0,1000}cribdragg3r\/Alaris.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1120 = /.{0,1000}crimeware.{0,1000}\/zeus\.profile.{0,1000}/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1121 = /.{0,1000}crisprss\/PrintSpoofer.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1122 = /.{0,1000}cross_s4u\.c.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1123 = /.{0,1000}cross_s4u\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1124 = /.{0,1000}CrossC2\sbeacon.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1125 = /.{0,1000}CrossC2\.cna.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1126 = /.{0,1000}crossc2_entry.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1127 = /.{0,1000}crossc2_portscan\..{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1128 = /.{0,1000}crossc2_serverscan\..{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1129 = /.{0,1000}CrossC2Beacon.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1130 = /.{0,1000}CrossC2Kit\..{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1131 = /.{0,1000}CrossC2Kit\..{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1132 = /.{0,1000}CrossC2Kit\.git.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1133 = /.{0,1000}CrossC2Kit_demo.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1134 = /.{0,1000}crossc2kit_latest.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1135 = /.{0,1000}CrossC2Kit_Loader.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1136 = /.{0,1000}CrossC2Listener.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1137 = /.{0,1000}CrossC2MemScriptEng.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1138 = /.{0,1000}CrossC2Script.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1139 = /.{0,1000}CrossNet\.exe.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1140 = /.{0,1000}CRTInjectAsSystem.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1141 = /.{0,1000}CRTInjectElevated.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1142 = /.{0,1000}CRTInjectWithoutPid.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1143 = /.{0,1000}cs2modrewrite\.py.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string1144 = /.{0,1000}cs2nginx\.py.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1145 = /.{0,1000}CS\-Avoid\-killing.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1146 = /.{0,1000}CS\-BOFs\/lsass.{0,1000}/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1147 = /.{0,1000}CSharpNamedPipeLoader.{0,1000}/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1148 = /.{0,1000}csload\.net\/.{0,1000}\/muma\..{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1149 = /.{0,1000}csOnvps.{0,1000}teamserver.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1150 = /.{0,1000}CS\-Remote\-OPs\-BOF.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string1151 = /.{0,1000}CSSG_load\.cna.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1152 = /.{0,1000}cs\-token\-vault\.git.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1153 = /.{0,1000}cube0x0\/LdapSignCheck.{0,1000}/ nocase ascii wide
        // Description: Various Aggressor Scripts I've Created.
        // Reference: https://github.com/offsecginger/AggressorScripts
        $string1154 = /.{0,1000}custom_payload_generator\..{0,1000}/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1155 = /.{0,1000}CustomKeyboardLayoutPersistence.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1156 = /.{0,1000}CVE_20.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1157 = /.{0,1000}cve\-20\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1158 = /.{0,1000}cve\-20\.x86\.dll.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1159 = /.{0,1000}DallasFR\/Cobalt\-Clip.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1160 = /.{0,1000}darkr4y\/geacon.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1161 = /.{0,1000}dcsync\@protonmail\.com.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1162 = /.{0,1000}dcsyncattack\(.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1163 = /.{0,1000}dcsyncattack\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1164 = /.{0,1000}dcsyncclient\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1165 = /.{0,1000}dcsyncclient\.py.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1166 = /.{0,1000}DeEpinGh0st\/Erebus.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1167 = /.{0,1000}DefaultBeaconApi.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1168 = /.{0,1000}demo\-bof\.cna.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string1169 = /.{0,1000}detect\-hooksx64\..{0,1000}/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1170 = /.{0,1000}DisableAllWindowsSoftwareFirewalls.{0,1000}/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1171 = /.{0,1000}disableeventvwr\/.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike addons to interact with clipboard
        // Reference: https://github.com/DallasFR/Cobalt-Clip
        $string1172 = /.{0,1000}dll\\reflective_dll\..{0,1000}/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1173 = /.{0,1000}dll_hijack_hunter.{0,1000}/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1174 = /.{0,1000}DLL_Imports_BOF.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1175 = /.{0,1000}DLL_TO_HIJACK_WIN10.{0,1000}/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1176 = /.{0,1000}DLL\-Hijack\-Search\-Order\-BOF.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1177 = /.{0,1000}dllinject\s.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1178 = /.{0,1000}dllload\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1179 = /.{0,1000}dns_beacon_beacon.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1180 = /.{0,1000}dns_beacon_dns_idle.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1181 = /.{0,1000}dns_beacon_dns_sleep.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1182 = /.{0,1000}dns_beacon_dns_stager_prepend.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1183 = /.{0,1000}dns_beacon_dns_stager_subhost.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1184 = /.{0,1000}dns_beacon_dns_ttl.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1185 = /.{0,1000}dns_beacon_get_A.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1186 = /.{0,1000}dns_beacon_get_TXT.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1187 = /.{0,1000}dns_beacon_maxdns.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1188 = /.{0,1000}dns_beacon_ns_response.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1189 = /.{0,1000}dns_beacon_put_metadata.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1190 = /.{0,1000}dns_beacon_put_output.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1191 = /.{0,1000}dns_redir\.sh\s.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1192 = /.{0,1000}dns_stager_prepend.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1193 = /.{0,1000}dns_stager_prepend.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1194 = /.{0,1000}\'dns_stager_prepend\'.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1195 = /.{0,1000}dns_stager_subhost.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1196 = /.{0,1000}dns_stager_subhost.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1197 = /.{0,1000}\'dns_stager_subhost\'.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1198 = /.{0,1000}dns\-beacon\s.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1199 = /.{0,1000}dnspayload\.bin.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1200 = /.{0,1000}do_attack\(.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string1201 = /.{0,1000}Doge\-Loader.{0,1000}xor\.go.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1202 = /.{0,1000}douknowwhoami\?d.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1203 = /.{0,1000}dr0op\/CrossNet.{0,1000}/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1204 = /.{0,1000}DReverseProxy\.git.{0,1000}/ nocase ascii wide
        // Description: A tool that can perform reverse proxy and cs online without going online
        // Reference: https://github.com/Daybr4ak/C2ReverseProxy
        $string1205 = /.{0,1000}DReverseServer\.go.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1206 = /.{0,1000}drop_malleable_unknown_.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1207 = /.{0,1000}drop_malleable_with_invalid_.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1208 = /.{0,1000}drop_malleable_without_.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1209 = /.{0,1000}dropper32\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1210 = /.{0,1000}dropper64\.exe.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) Creation Helper
        // Reference: https://github.com/dtmsecurity/bof_helper
        $string1211 = /.{0,1000}dtmsecurity\/bof_helper.{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1212 = /.{0,1000}Dumpert\.bin.{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1213 = /.{0,1000}Dumpert\.exe.{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1214 = /.{0,1000}Dumpert\-Aggressor.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1215 = /.{0,1000}DumpProcessByName.{0,1000}/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1216 = /.{0,1000}DumpShellcode\.exe.{0,1000}/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1217 = /.{0,1000}dumpXor\.exe\s.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1218 = /.{0,1000}EasyPersistent\.cna.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1219 = /.{0,1000}elevate\sjuicypotato\s.{0,1000}/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1220 = /.{0,1000}elevate\sPrintspoofer.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1221 = /.{0,1000}elevate\ssvc\-exe\s.{0,1000}/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1222 = /.{0,1000}ELFLoader\.c.{0,1000}/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1223 = /.{0,1000}ELFLoader\.h.{0,1000}/ nocase ascii wide
        // Description: This is a ELF object in memory loader/runner. The goal is to create a single elf loader that can be used to run follow on capabilities across all x86_64 and x86 nix operating systems.
        // Reference: https://github.com/trustedsec/ELFLoader
        $string1224 = /.{0,1000}ELFLoader\.out.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1225 = /.{0,1000}empire\sAttackServers.{0,1000}/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1226 = /.{0,1000}EncodeGroup\/AggressiveProxy.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string1227 = /.{0,1000}EncodeGroup\/UAC\-SilentClean.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1228 = /.{0,1000}encrypt\/encryptFile\.go.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1229 = /.{0,1000}encrypt\/encryptUrl\.go.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1230 = /.{0,1000}EncryptShellcode\(.{0,1000}/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1231 = /.{0,1000}engjibo\/NetUser.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to identify processes with the CLR loaded with a goal of identifying SpawnTo / injection candidates.
        // Reference: https://gist.github.com/G0ldenGunSec/8ca0e853dd5637af2881697f8de6aecc
        $string1232 = /.{0,1000}EnumCLR\.exe.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1233 = /.{0,1000}Erebus\/.{0,1000}spacerunner.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1234 = /.{0,1000}EspressoCake\/PPLDump_BOF.{0,1000}/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1235 = /.{0,1000}EventAggregation\.dll\.bak.{0,1000}/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1236 = /.{0,1000}eventspy\.cna.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1237 = /.{0,1000}EventSub\-Aggressor\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1238 = /.{0,1000}EventViewerUAC\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1239 = /.{0,1000}EventViewerUAC\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1240 = /.{0,1000}EventViewerUAC\.x64.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string1241 = /.{0,1000}EventViewerUAC\.x86.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1242 = /.{0,1000}EventViewerUAC_BOF.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1243 = /.{0,1000}eventvwr_elevator.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/Octoberfest7/EventViewerUAC_BOF
        $string1244 = /.{0,1000}EVUAC\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1245 = /.{0,1000}ewby\/Mockingjay_BOF.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1246 = /.{0,1000}example\-bof\.sln.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1247 = /.{0,1000}execmethod.{0,1000}PowerPick.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1248 = /.{0,1000}execmethod.{0,1000}PowerShell.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1249 = /.{0,1000}execute_bof\s.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1250 = /.{0,1000}execute\-assembly\s.{0,1000}\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1251 = /.{0,1000}executepersistence.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1252 = /.{0,1000}Export\-PowerViewCSV.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1253 = /.{0,1000}extract_reflective_loader.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1254 = /.{0,1000}Fiesta\sExploit\sKit.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1255 = /.{0,1000}FileControler\/FileControler_x64\.dll.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1256 = /.{0,1000}FileControler\/FileControler_x86\.dll.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1257 = /.{0,1000}find_payload\(.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1258 = /.{0,1000}findgpocomputeradmin.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1259 = /.{0,1000}Find\-GPOComputerAdmin.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1260 = /.{0,1000}Find\-InterestingDomainAcl.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1261 = /.{0,1000}findinterestingdomainsharefile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1262 = /.{0,1000}Find\-InterestingDomainShareFile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1263 = /.{0,1000}findlocaladminaccess.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1264 = /.{0,1000}findlocaladminaccess.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1265 = /.{0,1000}Find\-LocalAdminAccess.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1266 = /.{0,1000}Find\-LocalAdminAccess.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1267 = /.{0,1000}FindModule\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1268 = /.{0,1000}FindObjects\-BOF.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1269 = /.{0,1000}FindProcessTokenAndDuplicate.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles.
        // Reference: https://github.com/outflanknl/FindObjects-BOF
        $string1270 = /.{0,1000}FindProcHandle\s.{0,1000}lsass.{0,1000}/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1271 = /.{0,1000}Firewall_Walker_BOF.{0,1000}/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string1272 = /.{0,1000}fishing_with_hollowing.{0,1000}/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1273 = /.{0,1000}foreign_access\.cna.{0,1000}/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1274 = /.{0,1000}foreign_lsass\s.{0,1000}\s.{0,1000}/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1275 = /.{0,1000}foreign_lsass\.c.{0,1000}/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1276 = /.{0,1000}foreign_lsass\.x64.{0,1000}/ nocase ascii wide
        // Description: LSASS Dumping With Foreign Handles
        // Reference: https://github.com/alfarom256/BOF-ForeignLsass
        $string1277 = /.{0,1000}foreign_lsass\.x86.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1278 = /.{0,1000}\-\-format\-string\sziiiiizzzb\s.{0,1000}\s/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1279 = /.{0,1000}\-\-format\-string\sziiiiizzzib\s.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1280 = /.{0,1000}fortra\/No\-Consolation.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1281 = /.{0,1000}fucksetuptools.{0,1000}/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string1282 = /.{0,1000}FuckThatPacker\..{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1283 = /.{0,1000}FunnyWolf\/pystinger.{0,1000}/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string1284 = /.{0,1000}fw_walk\sdisable.{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1285 = /.{0,1000}G0ldenGunSec\/GetWebDAVStatus.{0,1000}/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1286 = /.{0,1000}GadgetToJScript\.exe\s\-a\s.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1287 = /.{0,1000}Gality369\/CS\-Loader.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1288 = /.{0,1000}gather\/keylogger.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1289 = /.{0,1000}geacon.{0,1000}\/cmd\/.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1290 = /.{0,1000}genCrossC2\..{0,1000}/ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1291 = /.{0,1000}generate_beacon.{0,1000}/ nocase ascii wide
        // Description: beacon generator
        // Reference: https://github.com/eddiezab/aggressor-scripts/tree/master
        $string1292 = /.{0,1000}generate\-rotating\-beacon\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1293 = /.{0,1000}GeorgePatsias\/ScareCrow.{0,1000}/ nocase ascii wide
        // Description: This aggressor script uses a beacon's note field to indicate the health status of a beacon.
        // Reference: https://github.com/Cobalt-Strike/beacon_health_check
        $string1294 = /.{0,1000}get_BeaconHealthCheck_settings.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1295 = /.{0,1000}get_dns_dnsidle.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1296 = /.{0,1000}get_dns_sleep.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1297 = /.{0,1000}get_password_policy\.x64\..{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1298 = /.{0,1000}get_password_policy\.x86\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1299 = /.{0,1000}get_post_ex_pipename_list.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1300 = /.{0,1000}get_post_ex_spawnto_x.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1301 = /.{0,1000}get_process_inject_allocator.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1302 = /.{0,1000}get_process_inject_bof_allocator.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1303 = /.{0,1000}get_process_inject_execute.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1304 = /.{0,1000}get_stage_allocator.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1305 = /.{0,1000}get_stage_magic_mz_64.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1306 = /.{0,1000}get_stage_magic_mz_86.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1307 = /.{0,1000}get_stage_magic_pe.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1308 = /.{0,1000}get_virtual_Hook_address.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1309 = /.{0,1000}getAggressorClient.{0,1000}/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1310 = /.{0,1000}Get\-BeaconAPI.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1311 = /.{0,1000}Get\-CachedRDPConnection.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1312 = /.{0,1000}getCrossC2Beacon.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1313 = /.{0,1000}getCrossC2Site.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1314 = /.{0,1000}getdomainspnticket.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1315 = /.{0,1000}Get\-DomainSPNTicket.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1316 = /.{0,1000}getexploitablesystem.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1317 = /.{0,1000}Get\-ExploitableSystem.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1318 = /.{0,1000}GetHijackableDllName.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1319 = /.{0,1000}GetNTLMChallengeBase64.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1320 = /.{0,1000}GetShellcode\(.{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1321 = /.{0,1000}GetWebDAVStatus\.csproj.{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1322 = /.{0,1000}GetWebDAVStatus\.sln.{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1323 = /.{0,1000}GetWebDAVStatus_DotNet.{0,1000}/ nocase ascii wide
        // Description: Determine if the WebClient Service (WebDAV) is running on a remote system
        // Reference: https://github.com/G0ldenGunSec/GetWebDAVStatus
        $string1324 = /.{0,1000}GetWebDAVStatus_x64\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1325 = /.{0,1000}getwmiregcachedrdpconnection.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1326 = /.{0,1000}Get\-WMIRegCachedRDPConnection.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1327 = /.{0,1000}getwmireglastloggedon.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1328 = /.{0,1000}Get\-WMIRegLastLoggedOn.{0,1000}/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1329 = /.{0,1000}gexplorer\.exe.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1330 = /.{0,1000}GhostPack\/Koh.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1331 = /.{0,1000}github.{0,1000}\/MoveKit\.git.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1332 = /.{0,1000}github\.com\/k8gege.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1333 = /.{0,1000}github\.com\/rasta\-mouse\/.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1334 = /.{0,1000}github\.com\/SpiderLabs\/.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1335 = /.{0,1000}gloxec\/CrossC2.{0,1000}/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1336 = /.{0,1000}go_shellcode_encode\.py.{0,1000}/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1337 = /.{0,1000}go\-shellcode\.py.{0,1000}/ nocase ascii wide
        // Description: generate shellcode
        // Reference: https://github.com/fcre1938/goShellCodeByPassVT
        $string1338 = /.{0,1000}goShellCodeByPassVT.{0,1000}/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1339 = /.{0,1000}hackbrowersdata\.cna.{0,1000}/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1340 = /.{0,1000}hack\-browser\-data\/.{0,1000}/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1341 = /.{0,1000}handlekatz\.x64\..{0,1000}/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1342 = /.{0,1000}handlekatz_bof\..{0,1000}/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1343 = /.{0,1000}Hangingsword\/HouQing.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1344 = /.{0,1000}hd\-launch\-cmd\s.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1345 = /.{0,1000}headers\/exploit\.h.{0,1000}/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1346 = /.{0,1000}headers\/HandleKatz\.h.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string1347 = /.{0,1000}Henkru\/cs\-token\-vault.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1348 = /.{0,1000}Hidden\.Desktop\.mp4.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1349 = /.{0,1000}HiddenDesktop\s.{0,1000}\s.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1350 = /.{0,1000}HiddenDesktop\..{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1351 = /.{0,1000}HiddenDesktop\.x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1352 = /.{0,1000}HiddenDesktop\.x86\.bin.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1353 = /.{0,1000}HiddenDesktop\.zip.{0,1000}/ nocase ascii wide
        // Description: DLL Hijack Search Order Enumeration BOF
        // Reference: https://github.com/EspressoCake/DLL-Hijack-Search-Order-BOF
        $string1354 = /.{0,1000}hijack_hunter\s.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1355 = /.{0,1000}hijack_remote_thread.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1356 = /.{0,1000}HiveJack\-Console\.exe.{0,1000}/ nocase ascii wide
        // Description: EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state. inject shellcode. hijack main thread with APC and execute shellcode
        // Reference: https://github.com/boku7/HOLLOW
        $string1357 = /.{0,1000}hollow\s.{0,1000}\.exe\s.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1358 = /.{0,1000}hollower\.Hollow\(.{0,1000}/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1359 = /.{0,1000}houqingv1\.0\.zip.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1360 = /.{0,1000}html\/js\/beacons\.js.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string1361 = /.{0,1000}http.{0,1000}\/zha0gongz1.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1362 = /.{0,1000}http.{0,1000}:3200\/manjusaka.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1363 = /.{0,1000}http.{0,1000}:801\/bq1iFEP2.{0,1000}/ nocase ascii wide
        // Description: Hou Qing-Advanced AV Evasion Tool For Red Team Ops
        // Reference: https://github.com/Hangingsword/HouQing
        $string1364 = /.{0,1000}http:\/\/127\.0\.0\.1:8000\/1\.jpg.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1365 = /.{0,1000}http_stager_client_header.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1366 = /.{0,1000}http_stager_server_append.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1367 = /.{0,1000}http_stager_server_header.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1368 = /.{0,1000}http_stager_server_prepend.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1369 = /.{0,1000}http_stager_uri_x64.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1370 = /.{0,1000}http_stager_uri_x86.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1371 = /.{0,1000}http1\.x64\.bin.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1372 = /.{0,1000}http1\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1373 = /.{0,1000}httpattack\.py.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike payload generator
        // Reference: https://github.com/dr0op/CrossNet-Beta
        $string1374 = /.{0,1000}httppayload\.bin.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1375 = /.{0,1000}http\-redwarden.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1376 = /.{0,1000}httprelayclient\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1377 = /.{0,1000}httprelayserver\.py.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1378 = /.{0,1000}\'http\-stager\'.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1379 = /.{0,1000}HVNC\sServer\.exe.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string1380 = /.{0,1000}HVNC\\\sServer.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string1381 = /.{0,1000}IcebreakerSecurity\/DelegationBOF.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1382 = /.{0,1000}IcebreakerSecurity\/PersistBOF.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1383 = /.{0,1000}imapattack\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1384 = /.{0,1000}imaprelayclient\.py.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1385 = /.{0,1000}impacket\..{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1386 = /.{0,1000}ImpersonateLocalService.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1387 = /.{0,1000}import\spe\.OBJExecutable.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1388 = /.{0,1000}include\sbeacon\.h.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1389 = /.{0,1000}include\sinjection\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1390 = /.{0,1000}inject\-amsiBypass\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1391 = /.{0,1000}inject\-amsiBypass\..{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1392 = /.{0,1000}inject\-assembly\s.{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1393 = /.{0,1000}inject\-assembly\.cna.{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1394 = /.{0,1000}injectassembly\.x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1395 = /.{0,1000}injectassembly\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)
        // Reference: https://github.com/boku7/injectEtwBypass
        $string1396 = /.{0,1000}injectEtwBypass.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string1397 = /.{0,1000}InjectShellcode.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1398 = /.{0,1000}inline\-execute\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string1399 = /.{0,1000}inline\-execute.{0,1000}whereami\.x64.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string1400 = /.{0,1000}InlineExecute\-Assembly.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string1401 = /.{0,1000}InlineWhispers\.py.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string1402 = /.{0,1000}InlineWhispers2.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1403 = /.{0,1000}install\simpacket.{0,1000}/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1404 = /.{0,1000}InvokeBloodHound.{0,1000}/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1405 = /.{0,1000}Invoke\-Bof\s.{0,1000}/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1406 = /.{0,1000}Invoke\-Bof\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1407 = /.{0,1000}invokechecklocaladminaccess.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1408 = /.{0,1000}Invoke\-CheckLocalAdminAccess.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1409 = /.{0,1000}invokeenumeratelocaladmin.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1410 = /.{0,1000}Invoke\-EnumerateLocalAdmin.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1411 = /.{0,1000}Invoke\-EnvBypass\..{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1412 = /.{0,1000}Invoke\-EventVwrBypass.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1413 = /.{0,1000}invokefilefinder.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1414 = /.{0,1000}Invoke\-FileFinder.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string1415 = /.{0,1000}Invoke\-HostEnum\s\-.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1416 = /.{0,1000}invokekerberoast.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1417 = /.{0,1000}Invoke\-Kerberoast.{0,1000}/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1418 = /.{0,1000}Invoke\-Phant0m.{0,1000}/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1419 = /.{0,1000}Invoke\-Phant0m\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1420 = /.{0,1000}invokeprocesshunter.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1421 = /.{0,1000}Invoke\-ProcessHunter.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1422 = /.{0,1000}invokereverttoself.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1423 = /.{0,1000}Invoke\-RevertToSelf.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1424 = /.{0,1000}invokesharefinder.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1425 = /.{0,1000}Invoke\-ShareFinder.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1426 = /.{0,1000}invokestealthuserhunter.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1427 = /.{0,1000}Invoke\-StealthUserHunter.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1428 = /.{0,1000}invokeuserhunter.{0,1000}/ nocase ascii wide
        // Description: PowerView menu for Cobalt Strike
        // Reference: https://github.com/tevora-threat/aggressor-powerview
        $string1429 = /.{0,1000}Invoke\-UserHunter.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1430 = /.{0,1000}Invoke\-WScriptBypassUAC.{0,1000}/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string1431 = /.{0,1000}jas502n\/bypassAV.{0,1000}/ nocase ascii wide
        // Description: Practice Go programming and implement CobaltStrike's Beacon in Go
        // Reference: https://github.com/darkr4y/geacon
        $string1432 = /.{0,1000}java\s\-jar\sBeaconTool\.jar.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1433 = /.{0,1000}Job\skilled\sand\sconsole\sdrained.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1434 = /.{0,1000}jquery\-c2\..{0,1000}\.profile.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1435 = /.{0,1000}jump\spsexec_psh.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1436 = /.{0,1000}jump\spsexec64.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1437 = /.{0,1000}jump\swinrm\s.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1438 = /.{0,1000}jump\swinrm.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1439 = /.{0,1000}jump\-exec\sscshell.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1440 = /.{0,1000}K8_CS_.{0,1000}\.rar.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1441 = /.{0,1000}k8gege\.org\/.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1442 = /.{0,1000}k8gege\/Ladon.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1443 = /.{0,1000}K8Ladon\.sln.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1444 = /.{0,1000}KaliLadon\..{0,1000}/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1445 = /.{0,1000}KBDPAYLOAD\.dll.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1446 = /.{0,1000}kdstab\s.{0,1000}\s\/CHECK.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1447 = /.{0,1000}kdstab\s.{0,1000}\s\/CLOSE.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1448 = /.{0,1000}kdstab\s.{0,1000}\s\/DRIVER.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1449 = /.{0,1000}kdstab\s.{0,1000}\s\/KILL.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1450 = /.{0,1000}kdstab\s.{0,1000}\s\/LIST.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1451 = /.{0,1000}kdstab\s.{0,1000}\s\/NAME.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1452 = /.{0,1000}kdstab\s.{0,1000}\s\/PID.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1453 = /.{0,1000}kdstab\s.{0,1000}\s\/SERVICE.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1454 = /.{0,1000}kdstab\s.{0,1000}\s\/STRIP.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1455 = /.{0,1000}kdstab\s.{0,1000}\s\/UNLOAD.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1456 = /.{0,1000}kdstab\.cna.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1457 = /.{0,1000}kerberoasting\.x64.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1458 = /.{0,1000}Kerberos\sabuse\s\(kerbeus\sBOF\).{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1459 = /.{0,1000}kerberos.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1460 = /.{0,1000}Kerbeus\s.{0,1000}\sby\sRalfHacker.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1461 = /.{0,1000}kerbeus_cs\.cna.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1462 = /.{0,1000}kerbeus_havoc\.py.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1463 = /.{0,1000}Kerbeus\-BOF\-main.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1464 = /.{0,1000}kernelcallbacktable\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1465 = /.{0,1000}kernelcallbacktable\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1466 = /.{0,1000}kernelcallbacktable\.x86.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1467 = /.{0,1000}kernelcallbacktable\.x86.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1468 = /.{0,1000}KernelMii\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1469 = /.{0,1000}KernelMii\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1470 = /.{0,1000}KernelMii\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1471 = /.{0,1000}KernelMii\.x86\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string1472 = /.{0,1000}KernelMii\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1473 = /.{0,1000}killdefender\scheck.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1474 = /.{0,1000}killdefender\skill.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1475 = /.{0,1000}KillDefender\.x64.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1476 = /.{0,1000}KillDefender\.x64\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of pwn1sher's KillDefender
        // Reference: https://github.com/Octoberfest7/KillDefender_BOF
        $string1477 = /.{0,1000}KillDefender_BOF.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1478 = /.{0,1000}killdefender_bof.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1479 = /.{0,1000}kirbi\.tickets.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1480 = /.{0,1000}koh\sfilter\sadd\sSID.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1481 = /.{0,1000}koh\sfilter\slist.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1482 = /.{0,1000}koh\sfilter\sremove\sSID.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1483 = /.{0,1000}koh\sfilter\sreset.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1484 = /.{0,1000}koh\sgroups\sLUID.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1485 = /.{0,1000}koh\simpersonate\sLUID.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1486 = /.{0,1000}koh\srelease\sall.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1487 = /.{0,1000}koh\srelease\sLUID.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1488 = /.{0,1000}Koh\.exe\scapture.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1489 = /.{0,1000}Koh\.exe\slist.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string1490 = /.{0,1000}Koh\.exe\smonitor.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1491 = /.{0,1000}krb_asktgs\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1492 = /.{0,1000}krb_asktgt\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1493 = /.{0,1000}krb_asreproasting.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1494 = /.{0,1000}krb_changepw\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1495 = /.{0,1000}krb_cross_s4u\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1496 = /.{0,1000}krb_describe\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1497 = /.{0,1000}krb_dump\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1498 = /.{0,1000}krb_hash\s\/password.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1499 = /.{0,1000}krb_klist\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1500 = /.{0,1000}krb_ptt\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1501 = /.{0,1000}krb_purge\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1502 = /.{0,1000}krb_renew\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1503 = /.{0,1000}krb_s4u\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1504 = /.{0,1000}krb_tgtdeleg\s\/.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1505 = /.{0,1000}krb_tgtdeleg\(.{0,1000}\).{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1506 = /.{0,1000}krb_triage\s\/.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1507 = /.{0,1000}krb5\/kerberosv5\.py.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1508 = /.{0,1000}krbasktgt\s\/.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1509 = /.{0,1000}krbcredccache\.py.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike UDRL for memory scanner evasion.
        // Reference: https://github.com/kyleavery/AceLdr
        $string1510 = /.{0,1000}kyleavery\/AceLdr.{0,1000}/ nocase ascii wide
        // Description: Inject .NET assemblies into an existing process
        // Reference: https://github.com/kyleavery/inject-assembly
        $string1511 = /.{0,1000}kyleavery\/inject\-assembly.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1512 = /.{0,1000}Ladon\s.{0,1000}\sAllScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1513 = /.{0,1000}Ladon\s.{0,1000}\sCiscoScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1514 = /.{0,1000}Ladon\s.{0,1000}\sOnlineIP.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1515 = /.{0,1000}Ladon\s.{0,1000}\sOnlinePC.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1516 = /.{0,1000}Ladon\s.{0,1000}\sOsScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1517 = /.{0,1000}Ladon\s.{0,1000}\sOxidScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1518 = /.{0,1000}Ladon\s.{0,1000}\.txt\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1519 = /.{0,1000}Ladon\s.{0,1000}DeBase64.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1520 = /.{0,1000}Ladon\s.{0,1000}FtpScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1521 = /.{0,1000}Ladon\s.{0,1000}LdapScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1522 = /.{0,1000}Ladon\s.{0,1000}SMBGhost.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1523 = /.{0,1000}Ladon\s.{0,1000}SmbHashScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1524 = /.{0,1000}Ladon\s.{0,1000}SmbScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1525 = /.{0,1000}Ladon\s.{0,1000}SshScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1526 = /.{0,1000}Ladon\s.{0,1000}TomcatScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1527 = /.{0,1000}Ladon\s.{0,1000}VncScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1528 = /.{0,1000}Ladon\s.{0,1000}WebScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1529 = /.{0,1000}Ladon\s.{0,1000}WinrmScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1530 = /.{0,1000}Ladon\s.{0,1000}WmiHashScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1531 = /.{0,1000}Ladon\s.{0,1000}WmiScan.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1532 = /.{0,1000}Ladon\sActiveAdmin.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1533 = /.{0,1000}Ladon\sActiveGuest.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1534 = /.{0,1000}Ladon\sAdiDnsDump\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1535 = /.{0,1000}Ladon\sat\sc:.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1536 = /.{0,1000}Ladon\sAtExec.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1537 = /.{0,1000}Ladon\sAutoRun.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1538 = /.{0,1000}Ladon\sBadPotato.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1539 = /.{0,1000}Ladon\sBypassUAC.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1540 = /.{0,1000}Ladon\sCheckDoor.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1541 = /.{0,1000}Ladon\sClslog.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1542 = /.{0,1000}Ladon\sCmdDll\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1543 = /.{0,1000}Ladon\scmdline.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1544 = /.{0,1000}Ladon\sCVE\-.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1545 = /.{0,1000}Ladon\sDirList.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1546 = /.{0,1000}Ladon\sDraytekExp.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1547 = /.{0,1000}Ladon\sDumpLsass.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1548 = /.{0,1000}Ladon\sEnableDotNet.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1549 = /.{0,1000}Ladon\sEnumProcess.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1550 = /.{0,1000}Ladon\sEnumShare.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1551 = /.{0,1000}Ladon\sExploit.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1552 = /.{0,1000}Ladon\sFindIP\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1553 = /.{0,1000}Ladon\sFirefoxCookie.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1554 = /.{0,1000}Ladon\sFirefoxHistory.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1555 = /.{0,1000}Ladon\sFirefoxPwd.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1556 = /.{0,1000}Ladon\sForExec\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1557 = /.{0,1000}Ladon\sFtpDownLoad\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1558 = /.{0,1000}Ladon\sFtpServer\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1559 = /.{0,1000}Ladon\sGetDomainIP.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1560 = /.{0,1000}Ladon\sgethtml\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1561 = /.{0,1000}Ladon\sGetPipe.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1562 = /.{0,1000}Ladon\sGetSystem.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1563 = /.{0,1000}Ladon\sIISdoor.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1564 = /.{0,1000}Ladon\sIISpwd.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1565 = /.{0,1000}Ladon\sMssqlCmd\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1566 = /.{0,1000}Ladon\snetsh\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1567 = /.{0,1000}Ladon\snoping\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1568 = /.{0,1000}Ladon\sOpen3389.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1569 = /.{0,1000}Ladon\sPowerCat\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1570 = /.{0,1000}Ladon\sPrintNightmare.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1571 = /.{0,1000}Ladon\spsexec.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1572 = /.{0,1000}Ladon\sQueryAdmin.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1573 = /.{0,1000}Ladon\sRdpHijack.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1574 = /.{0,1000}Ladon\sReadFile\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1575 = /.{0,1000}Ladon\sRegAuto.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1576 = /.{0,1000}Ladon\sReverseHttps.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1577 = /.{0,1000}Ladon\sReverseTcp\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1578 = /.{0,1000}Ladon\sRevShell\-.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1579 = /.{0,1000}Ladon\sRunas.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1580 = /.{0,1000}Ladon\sRunPS\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1581 = /.{0,1000}Ladon\ssc\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1582 = /.{0,1000}Ladon\sSetSignAuth.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1583 = /.{0,1000}Ladon\sSmbExec\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1584 = /.{0,1000}Ladon\sSniffer.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1585 = /.{0,1000}Ladon\sSshExec\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1586 = /.{0,1000}Ladon\sSweetPotato.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1587 = /.{0,1000}Ladon\sTcpServer\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1588 = /.{0,1000}Ladon\sUdpServer.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1589 = /.{0,1000}Ladon\sWebShell.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1590 = /.{0,1000}Ladon\swhoami.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1591 = /.{0,1000}Ladon\sWifiPwd.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1592 = /.{0,1000}Ladon\swmiexec.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1593 = /.{0,1000}Ladon\sWmiExec2\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1594 = /.{0,1000}Ladon\sXshellPwd.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1595 = /.{0,1000}Ladon\sZeroLogon.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1596 = /.{0,1000}Ladon40\sBypassUAC.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1597 = /.{0,1000}Ladon911.{0,1000}\.ps1/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1598 = /.{0,1000}Ladon911\.exe.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1599 = /.{0,1000}Ladon911_.{0,1000}\.rar.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1600 = /.{0,1000}LadonExp\.exe.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1601 = /.{0,1000}LadonGUI\.exe.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1602 = /.{0,1000}LadonLib\.rar.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string1603 = /.{0,1000}LadonStudy\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1604 = /.{0,1000}lastpass\.x86.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1605 = /.{0,1000}lastpass\/process_lp_files\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1606 = /.{0,1000}ldap_shell\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1607 = /.{0,1000}ldapattack\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1608 = /.{0,1000}ldaprelayclient\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1609 = /.{0,1000}LdapSignCheck\.exe.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1610 = /.{0,1000}LdapSignCheck\.Natives.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1611 = /.{0,1000}LdapSignCheck\.sln.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1612 = /.{0,1000}ldapsigncheck\.x64\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string1613 = /.{0,1000}ldapsigncheck\.x86\..{0,1000}/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1614 = /.{0,1000}LetMeOutSharp\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1615 = /.{0,1000}libs\/bofalloc.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1616 = /.{0,1000}libs\/bofentry.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1617 = /.{0,1000}libs\/bofhelper.{0,1000}/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1618 = /.{0,1000}LiquidSnake\.exe.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1619 = /.{0,1000}llsrpc_\#\#.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1620 = /.{0,1000}load\saggressor\sscript.{0,1000}/ nocase ascii wide
        // Description: POC tool to convert CobaltStrike BOF files to raw shellcode
        // Reference: https://github.com/FalconForceTeam/BOF2shellcode
        $string1621 = /.{0,1000}load_sc\.exe\s.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1622 = /.{0,1000}Load\-BeaconParameters.{0,1000}/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string1623 = /.{0,1000}Load\-Bof\(.{0,1000}/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1624 = /.{0,1000}loader\/loader\/loader\.c.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1625 = /.{0,1000}localS4U2Proxy\.tickets.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1626 = /.{0,1000}logToBeaconLog.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1627 = /.{0,1000}lsarpc_\#\#.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1628 = /.{0,1000}Magnitude\sExploit\sKit.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1629 = /.{0,1000}main_air_service\-probes\.go.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1630 = /.{0,1000}main_pro_service\-probes\.go.{0,1000}/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1631 = /.{0,1000}makebof\.bat.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike toolkit
        // Reference: https://github.com/1135/1135-CobaltStrike-ToolKit
        $string1632 = /.{0,1000}Malleable\sC2\sFiles.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string1633 = /.{0,1000}Malleable\sPE\/Stage.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1634 = /.{0,1000}malleable_redirector\.py.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1635 = /.{0,1000}malleable_redirector_hidden_api_endpoint.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1636 = /.{0,1000}Malleable\-C2\-Profiles.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1637 = /.{0,1000}Malleable\-C2\-Randomizer.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1638 = /.{0,1000}Malleable\-C2\-Randomizer.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1639 = /.{0,1000}malleable\-redirector\-config.{0,1000}/ nocase ascii wide
        // Description: Manual Map DLL injection implemented with Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/tomcarver16/BOF-DLL-Inject
        $string1640 = /.{0,1000}mandllinject\s.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1641 = /.{0,1000}mdsecactivebreach\/CACTUSTORCH.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string1642 = /.{0,1000}med0x2e\/SigFlip.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1643 = /.{0,1000}memreader\s.{0,1000}access_token.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string1644 = /.{0,1000}MemReader_BoF\..{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1645 = /.{0,1000}meterpreter\..{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1646 = /.{0,1000}metsrv\.dll.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1647 = /.{0,1000}mgeeky\/RedWarden.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1648 = /.{0,1000}mimipenguin\.cna.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1649 = /.{0,1000}mimipenguin\.so.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1650 = /.{0,1000}mimipenguin_x32\.so.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1651 = /.{0,1000}minidump_add_memory_block.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1652 = /.{0,1000}minidump_add_memory64_block.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1653 = /.{0,1000}minidumpwritedump.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string1654 = /.{0,1000}MiniDumpWriteDump.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string1655 = /.{0,1000}miscbackdoorlnkhelp.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1656 = /.{0,1000}Mockingjay_BOF\.sln.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // Reference: https://github.com/ewby/Mockingjay_BOF
        $string1657 = /.{0,1000}Mockingjay_BOF\-main.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1658 = /.{0,1000}mojo_\#\#.{0,1000}/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1659 = /.{0,1000}moonD4rk\/HackBrowserData.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1660 = /.{0,1000}MoveKit\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1661 = /.{0,1000}move\-msbuild\s.{0,1000}\shttp\smove\.csproj.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Lateral Movement
        // Reference: https://github.com/0xthirteen/MoveKit
        $string1662 = /.{0,1000}move\-pre\-custom\-file\s.{0,1000}\.exe\s.{0,1000}/ nocase ascii wide
        // Description: backdoor c2
        // Reference: https://github.com/wahyuhadi/beacon-c2-go
        $string1663 = /.{0,1000}msfvemonpayload.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1664 = /.{0,1000}mssqlattack\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1665 = /.{0,1000}mssqlrelayclient\.py.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1666 = /.{0,1000}my_dump_my_pe.{0,1000}/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1667 = /.{0,1000}needle_sift\.x64.{0,1000}/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string1668 = /.{0,1000}needlesift\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1669 = /.{0,1000}netero1010\/Quser\-BOF.{0,1000}/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1670 = /.{0,1000}netero1010\/ServiceMove\-BOF.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1671 = /.{0,1000}netlogon_\#\#.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1672 = /.{0,1000}netuser_enum.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string1673 = /.{0,1000}netview_enum.{0,1000}/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1674 = /.{0,1000}NoApiUser\.exe.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1675 = /.{0,1000}noconsolation\s\/tmp\/.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1676 = /.{0,1000}noconsolation\s\-\-local\s.{0,1000}cmd\.exe.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1677 = /.{0,1000}noconsolation\s\-\-local\s.{0,1000}powershell\.exe.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1678 = /.{0,1000}No\-Consolation\.cna.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1679 = /.{0,1000}NoConsolation\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1680 = /.{0,1000}NoConsolation\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e spawning conhost.exe)
        // Reference: https://github.com/fortra/No-Consolation
        $string1681 = /.{0,1000}No\-Consolation\-main.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1682 = /.{0,1000}normal\/randomized\.profile.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1683 = /.{0,1000}ntcreatethread\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1684 = /.{0,1000}ntcreatethread\.x86.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string1685 = /.{0,1000}oab\-parse\.py.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1686 = /.{0,1000}obscuritylabs\/ase:latest.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1687 = /.{0,1000}obscuritylabs\/RAI\/.{0,1000}/ nocase ascii wide
        // Description: BOF combination of KillDefender and Backstab
        // Reference: https://github.com/Octoberfest7/KDStab
        $string1688 = /.{0,1000}Octoberfest7\/KDStab.{0,1000}/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1689 = /.{0,1000}OG\-Sadpanda\/SharpCat.{0,1000}/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string1690 = /.{0,1000}OG\-Sadpanda\/SharpSword.{0,1000}/ nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string1691 = /.{0,1000}OG\-Sadpanda\/SharpZippo.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1692 = /.{0,1000}On_Demand_C2\..{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1693 = /.{0,1000}On\-Demand_C2_BOF\..{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string1694 = /.{0,1000}OnDemandC2Class\.cs.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1695 = /.{0,1000}openBeaconBrowser.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1696 = /.{0,1000}openBeaconBrowser.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1697 = /.{0,1000}openBeaconConsole.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1698 = /.{0,1000}openBeaconConsole.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1699 = /.{0,1000}openBypassUACDialog.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1700 = /.{0,1000}openBypassUACDialog.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1701 = /.{0,1000}openGoldenTicketDialog.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1702 = /.{0,1000}openKeystrokeBrowser.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1703 = /.{0,1000}openPayloadGenerator.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1704 = /.{0,1000}openPayloadGeneratorDialog.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1705 = /.{0,1000}openPayloadHelper.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1706 = /.{0,1000}openPortScanner.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1707 = /.{0,1000}openPortScanner.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1708 = /.{0,1000}openSpearPhishDialog.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1709 = /.{0,1000}openWindowsExecutableStage.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon
        // Reference: https://github.com/optiv/Registry-Recon
        $string1710 = /.{0,1000}optiv\/Registry\-Recon.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1711 = /.{0,1000}optiv\/ScareCrow.{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string1712 = /.{0,1000}Outflank\-Dumpert\..{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1713 = /.{0,1000}outflanknl\/Recon\-AD.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string1714 = /.{0,1000}outflanknl\/Spray\-AD.{0,1000}/ nocase ascii wide
        // Description: s
        // Reference: https://github.com/outflanknl/WdToggle
        $string1715 = /.{0,1000}outflanknl\/WdToggle.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1716 = /.{0,1000}Outflank\-Recon\-AD.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1717 = /.{0,1000}output\/html\/data\/beacons\.json.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1718 = /.{0,1000}output\/payloads\/.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1719 = /.{0,1000}parse_aggressor_properties.{0,1000}/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1720 = /.{0,1000}parse_shellcode.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.
        // Reference: https://github.com/boku7/injectAmsiBypass
        $string1721 = /.{0,1000}patchAmsiOpenSession.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1722 = /.{0,1000}payload_bootstrap_hint.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1723 = /.{0,1000}payload_local.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1724 = /.{0,1000}payload_scripts\.cna.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1725 = /.{0,1000}payload_scripts\/sleepmask.{0,1000}/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1726 = /.{0,1000}payload_section\.cpp.{0,1000}/ nocase ascii wide
        // Description: Achieve execution using a custom keyboard layout
        // Reference: https://github.com/NtQuerySystemInformation/CustomKeyboardLayoutPersistence
        $string1727 = /.{0,1000}payload_section\.hpp.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string1728 = /.{0,1000}payloadgenerator\.py.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1729 = /.{0,1000}Perform\sAS\-REP\sroasting.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1730 = /.{0,1000}PersistBOF\.cna.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1731 = /.{0,1000}PersistenceBOF\.c.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1732 = /.{0,1000}PersistenceBOF\.exe.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1733 = /.{0,1000}persist\-ice\-junction\.o.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1734 = /.{0,1000}persist\-ice\-monitor\.o.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1735 = /.{0,1000}persist\-ice\-shortcut\.o.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1736 = /.{0,1000}persist\-ice\-time\.o.{0,1000}/ nocase ascii wide
        // Description: A BOF to automate common persistence tasks for red teamers
        // Reference: https://github.com/IcebreakerSecurity/PersistBOF
        $string1737 = /.{0,1000}persist\-ice\-xll\.o.{0,1000}/ nocase ascii wide
        // Description: Aggressor script to integrate Phant0m with Cobalt Strike
        // Reference: https://github.com/p292/Phant0m_cobaltstrike
        $string1738 = /.{0,1000}Phant0m_cobaltstrike.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1739 = /.{0,1000}\'pipename_stager\'.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string1740 = /.{0,1000}Pitty\sTiger\sRAT.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1741 = /.{0,1000}\-pk8gege\.org.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors Gray often ginkgo design
        // Reference: https://github.com/AlphabugX/csOnvps
        $string1742 = /.{0,1000}pkexec64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1743 = /.{0,1000}plug_getpass_nps\.dll.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1744 = /.{0,1000}plug_katz_nps\.exe.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string1745 = /.{0,1000}plug_qvte_nps\.exe.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1746 = /.{0,1000}PortBender\sbackdoor.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1747 = /.{0,1000}PortBender\sredirect.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1748 = /.{0,1000}PortBender\.cna.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1749 = /.{0,1000}PortBender\.cpp.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1750 = /.{0,1000}portbender\.dll.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1751 = /.{0,1000}PortBender\.exe.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1752 = /.{0,1000}PortBender\.h.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1753 = /.{0,1000}PortBender\.sln.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1754 = /.{0,1000}PortBender\.zip.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string1755 = /.{0,1000}portscan_result\.cna.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1756 = /.{0,1000}portscan386\s.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1757 = /.{0,1000}portscan64\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1758 = /.{0,1000}post_ex_amsi_disable.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1759 = /.{0,1000}post_ex_keylogger.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1760 = /.{0,1000}post_ex_obfuscate.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1761 = /.{0,1000}Post_EX_Process_Name.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1762 = /.{0,1000}post_ex_smartinject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1763 = /.{0,1000}post_ex_spawnto_x64.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1764 = /.{0,1000}post_ex_spawnto_x86.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1765 = /.{0,1000}powershell_encode_oneliner.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1766 = /.{0,1000}powershell_encode_oneliner.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1767 = /.{0,1000}powershell_encode_stager.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1768 = /.{0,1000}powershell_encode_stager.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1769 = /.{0,1000}powershell\-import\s.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Aggressor script menu for Powerview/SharpView
        // Reference: https://github.com/tevora-threat/PowerView3-Aggressor
        $string1770 = /.{0,1000}PowerView3\-Aggressor.{0,1000}/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1771 = /.{0,1000}ppenum\.c.{0,1000}/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1772 = /.{0,1000}ppenum\.exe.{0,1000}/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1773 = /.{0,1000}ppenum\.x64\..{0,1000}/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1774 = /.{0,1000}ppenum\.x86\..{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1775 = /.{0,1000}ppl_dump\.x64.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1776 = /.{0,1000}ppldump\s.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string1777 = /.{0,1000}PPLDump_BOF\..{0,1000}/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1778 = /.{0,1000}pplfault\.cna.{0,1000}/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1779 = /.{0,1000}PPLFaultDumpBOF.{0,1000}/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1780 = /.{0,1000}PPLFaultPayload\.dll.{0,1000}/ nocase ascii wide
        // Description: Takes the original PPLFault and the original included DumpShellcode and combinds it all into a BOF targeting cobalt strike.
        // Reference: https://github.com/trustedsec/PPLFaultDumpBOF
        $string1781 = /.{0,1000}PPLFaultTemp.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1782 = /.{0,1000}praetorian\.antihacker.{0,1000}/ nocase ascii wide
        // Description: PortBender is a TCP port redirection utility that allows a red team operator to redirect inbound traffic 
        // Reference: https://github.com/praetorian-inc/PortBender
        $string1783 = /.{0,1000}praetorian\-inc\/PortBender.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1784 = /.{0,1000}prepareResponseForHiddenAPICall.{0,1000}/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1785 = /.{0,1000}PrintSpoofer\-.{0,1000}/ nocase ascii wide
        // Description: Reflection dll implementation of PrintSpoofer used in conjunction with Cobalt Strike
        // Reference: https://github.com/crisprss/PrintSpoofer
        $string1786 = /.{0,1000}PrintSpoofer\..{0,1000}/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1787 = /.{0,1000}process_imports\.cna.{0,1000}/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1788 = /.{0,1000}process_imports\.x64.{0,1000}/ nocase ascii wide
        // Description: A BOF to parse the imports of a provided PE-file. optionally extracting symbols on a per-dll basis.
        // Reference: https://github.com/EspressoCake/DLL_Imports_BOF
        $string1789 = /.{0,1000}process_imports_api\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1790 = /.{0,1000}process_inject_allocator.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1791 = /.{0,1000}process_inject_bof_allocator.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1792 = /.{0,1000}process_inject_bof_reuse_memory.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1793 = /.{0,1000}process_inject_execute.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1794 = /.{0,1000}process_inject_min_alloc.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1795 = /.{0,1000}process_inject_startrwx.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1796 = /.{0,1000}Process_Inject_Struct.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1797 = /.{0,1000}process_inject_transform_x.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1798 = /.{0,1000}process_inject_userwx.{0,1000}/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1799 = /.{0,1000}process_protection_enum\s.{0,1000}/ nocase ascii wide
        // Description: A BOF port of the research of @thefLinkk and @codewhitesec
        // Reference: https://github.com//EspressoCake/HandleKatz_BOF
        $string1800 = /.{0,1000}process_protection_enum.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1801 = /.{0,1000}process_protection_enum\..{0,1000}/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1802 = /.{0,1000}Process_Protection_Level_BOF\..{0,1000}/ nocase ascii wide
        // Description: A Syscall-only BOF file intended to grab process protection attributes. limited to a handful that Red Team operators and pentesters would commonly be interested in.
        // Reference: https://github.com/EspressoCake/Process_Protection_Level_BOF
        $string1803 = /.{0,1000}Process_Protection_Level_BOF\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1804 = /.{0,1000}ProcessDestroy\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1805 = /.{0,1000}ProcessDestroy\.x64\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1806 = /.{0,1000}ProcessDestroy\.x86.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1807 = /.{0,1000}ProcessDestroy\.x86\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1808 = /.{0,1000}process\-inject\s.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string1809 = /.{0,1000}processinject_min_alloc.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1810 = /.{0,1000}ProgIDsUACBypass\..{0,1000}/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1811 = /.{0,1000}Proxy\sShellcode\sHandler.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1812 = /.{0,1000}proxychains.{0,1000}scshell.{0,1000}/ nocase ascii wide
        // Description: Project to enumerate proxy configurations and generate shellcode from CobaltStrike
        // Reference: https://github.com/EncodeGroup/AggressiveProxy
        $string1813 = /.{0,1000}proxyshellcodeurl.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1814 = /.{0,1000}PSconfusion\.py.{0,1000}/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string1815 = /.{0,1000}PSEXEC_PSH\s.{0,1000}/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/pureqh/bypassAV
        $string1816 = /.{0,1000}pureqh\/bypassAV.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1817 = /.{0,1000}pwn1sher\/CS\-BOFs.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1818 = /.{0,1000}pycobalt\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1819 = /.{0,1000}pycobalt\/aggressor.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1820 = /.{0,1000}pycobalt_debug_on.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1821 = /.{0,1000}pycobalt_path.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1822 = /.{0,1000}pycobalt_python.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1823 = /.{0,1000}pycobalt_timeout.{0,1000}/ nocase ascii wide
        // Description: Quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles
        // Reference: https://github.com/CodeXTF2/Burp2Malleable
        $string1824 = /.{0,1000}pyMalleableC2.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1825 = /.{0,1000}pystinger_for_darkshadow.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1826 = /.{0,1000}python\sscshell.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1827 = /.{0,1000}python2\?\?\/generator\.py.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1828 = /.{0,1000}python2\?\?\/PyLoader\.py.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1829 = /.{0,1000}python3\sscshell.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1830 = /.{0,1000}python3\?\?\/generator\.py.{0,1000}/ nocase ascii wide
        // Description: CS anti-killing including python version and C version
        // Reference: https://github.com/Gality369/CS-Loader
        $string1831 = /.{0,1000}python3\?\?\/PyLoader\.py.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1832 = /.{0,1000}QUAPCInjectAsSystem.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1833 = /.{0,1000}QUAPCInjectElevated.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1834 = /.{0,1000}QUAPCInjectFakecmd.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1835 = /.{0,1000}QUAPCInjectFakecmd.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1836 = /.{0,1000}QUAPCInjectWithoutPid.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1837 = /.{0,1000}quser\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF for quser.exe implementation using Windows API
        // Reference: https://github.com/netero1010/Quser-BOF
        $string1838 = /.{0,1000}quser\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string1839 = /.{0,1000}QXh4OEF4eDhBeHg4QXh4OA\=\=.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1840 = /.{0,1000}RAI\/ase_docker.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1841 = /.{0,1000}rai\-attack\-servers\..{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1842 = /.{0,1000}rai\-redirector\-dns.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1843 = /.{0,1000}rai\-redirector\-http.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1844 = /.{0,1000}RalfHacker\/Kerbeus\-BOF.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1845 = /.{0,1000}random_c2_profile.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1846 = /.{0,1000}random_c2profile\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1847 = /.{0,1000}random_user_agent\.params.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string1848 = /.{0,1000}random_user_agent\.user_agent.{0,1000}/ nocase ascii wide
        // Description: Simple BOF to read the protection level of a process
        // Reference: https://github.com/rasta-mouse/PPEnum
        $string1849 = /.{0,1000}rasta\-mouse\/PPEnum.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string1850 = /.{0,1000}rasta\-mouse\/TikiTorch.{0,1000}/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1851 = /.{0,1000}rdi_net_user\.cpp.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1852 = /.{0,1000}rdphijack\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1853 = /.{0,1000}rdphijack\.x86.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1854 = /.{0,1000}RDPHijack\-BOF.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1855 = /.{0,1000}RdpThief\..{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string1856 = /.{0,1000}read_cs_teamserver.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1857 = /.{0,1000}Recon\-AD\-.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1858 = /.{0,1000}Recon\-AD\-.{0,1000}\.sln.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1859 = /.{0,1000}Recon\-AD\-.{0,1000}\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1860 = /.{0,1000}Recon\-AD\-AllLocalGroups.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1861 = /.{0,1000}Recon\-AD\-Domain.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1862 = /.{0,1000}Recon\-AD\-LocalGroups.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1863 = /.{0,1000}Recon\-AD\-SPNs.{0,1000}/ nocase ascii wide
        // Description: Recon-AD an AD recon tool based on ADSI and reflective DLL s
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1864 = /.{0,1000}Recon\-AD\-Users\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1865 = /.{0,1000}redelk_backend_name_c2.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1866 = /.{0,1000}redelk_backend_name_decoy.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1867 = /.{0,1000}Red\-Team\-Infrastructure\-Wiki\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1868 = /.{0,1000}RedWarden\.py.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1869 = /.{0,1000}RedWarden\.test.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1870 = /.{0,1000}redwarden_access\.log.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike C2 Reverse proxy that fends off Blue Teams. AVs. EDRs. scanners through packet inspection and malleable profile correlation
        // Reference: https://github.com/mgeeky/RedWarden
        $string1871 = /.{0,1000}redwarden_redirector\.log.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1872 = /.{0,1000}reflective_dll\.dll.{0,1000}/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1873 = /.{0,1000}reflective_dll\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1874 = /.{0,1000}ReflectiveDll\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1875 = /.{0,1000}ReflectiveDll\.x86\.dll.{0,1000}/ nocase ascii wide
        // Description: reflective module for HackBrowserData
        // Reference: https://github.com/idiotc4t/Reflective-HackBrowserData
        $string1876 = /.{0,1000}Reflective\-HackBrowserData.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1877 = /.{0,1000}Remote\/lastpass\/lastpass\.x86\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1878 = /.{0,1000}Remote\/setuserpass\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1879 = /.{0,1000}Remote\/shspawnas.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1880 = /.{0,1000}Remote\/suspendresume\/.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1881 = /.{0,1000}remote\-exec\s.{0,1000}jump\s.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string1882 = /.{0,1000}remotereg\.cna.{0,1000}/ nocase ascii wide
        // Description: A protective and Low Level Shellcode Loader that defeats modern EDR systems.
        // Reference: https://github.com/cribdragg3r/Alaris
        $string1883 = /.{0,1000}replace_key_iv_shellcode.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1884 = /.{0,1000}RiccardoAncarani\/BOFs.{0,1000}/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1885 = /.{0,1000}RiccardoAncarani\/LiquidSnake.{0,1000}/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string1886 = /.{0,1000}RiccardoAncarani\/TaskShell.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string1887 = /.{0,1000}rkervella\/CarbonMonoxide.{0,1000}/ nocase ascii wide
        // Description: Collection of beacon object files for use with Cobalt Strike to facilitate
        // Reference: https://github.com/rookuu/BOFs
        $string1888 = /.{0,1000}rookuu\/BOFs\/.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1889 = /.{0,1000}rpcattack\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1890 = /.{0,1000}rpcrelayclient\.py.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1891 = /.{0,1000}rsmudge\/ElevateKit.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1892 = /.{0,1000}runasadmin\suac\-cmstplua.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1893 = /.{0,1000}runasadmin\suac\-token\-duplication.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1894 = /.{0,1000}RunOF\.exe\s\-.{0,1000}/ nocase ascii wide
        // Description: A tool to run object files mainly beacon object files (BOF) in .Net.
        // Reference: https://github.com/nettitude/RunOF
        $string1895 = /.{0,1000}RunOF\.Internals.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string1896 = /.{0,1000}rustbof\.cna.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string1897 = /.{0,1000}rvrsh3ll\/BOF_Collection.{0,1000}/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string1898 = /.{0,1000}rxwx\/cs\-rdll\-ipc\-example.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1899 = /.{0,1000}s4u\.x64\.c.{0,1000}/ nocase ascii wide
        // Description: BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // Reference: https://github.com/RalfHacker/Kerbeus-BOF
        $string1900 = /.{0,1000}s4u\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1901 = /.{0,1000}SafetyKatz\.exe.{0,1000}/ nocase ascii wide
        // Description: Use windows api to add users which can be used when net is unavailable
        // Reference: https://github.com/lengjibo/NetUser
        $string1902 = /.{0,1000}SamAdduser\.exe.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string1903 = /.{0,1000}samr_\#\#.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1904 = /.{0,1000}ScareCrow.{0,1000}\s\-encryptionmode\s.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1905 = /.{0,1000}ScareCrow.{0,1000}\s\-Evasion.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1906 = /.{0,1000}ScareCrow.{0,1000}\s\-Exec.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1907 = /.{0,1000}ScareCrow.{0,1000}\s\-injection.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1908 = /.{0,1000}ScareCrow.{0,1000}\s\-Loader\s.{0,1000}\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1909 = /.{0,1000}ScareCrow.{0,1000}\s\-noamsi.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1910 = /.{0,1000}ScareCrow.{0,1000}\s\-noetw.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1911 = /.{0,1000}ScareCrow.{0,1000}\s\-obfu.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1912 = /.{0,1000}ScareCrow.{0,1000}_darwin_amd64.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1913 = /.{0,1000}ScareCrow.{0,1000}_windows_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1914 = /.{0,1000}ScareCrow.{0,1000}KnownDLL.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1915 = /.{0,1000}ScareCrow.{0,1000}ProcessInjection.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike script for ScareCrow payloads intergration (EDR/AV evasion)
        // Reference: https://github.com/GeorgePatsias/ScareCrow-CobaltStrike
        $string1916 = /.{0,1000}ScareCrow\.cna.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1917 = /.{0,1000}ScareCrow\/Cryptor.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1918 = /.{0,1000}ScareCrow\/limelighter.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1919 = /.{0,1000}ScareCrow\/Loader.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1920 = /.{0,1000}ScareCrow\/Utils.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1921 = /.{0,1000}schshell\.cna.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string1922 = /.{0,1000}schtask_callback.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1923 = /.{0,1000}schtasks_elevator.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string1924 = /.{0,1000}schtasks_exploit\s.{0,1000}/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1925 = /.{0,1000}ScRunBase32\.exe.{0,1000}/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1926 = /.{0,1000}ScRunBase32\.py.{0,1000}/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1927 = /.{0,1000}ScRunBase64\.exe.{0,1000}/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string1928 = /.{0,1000}ScRunBase64\.py.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1929 = /.{0,1000}scshell.{0,1000}XblAuthManager.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1930 = /.{0,1000}SCShell\.exe.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1931 = /.{0,1000}scshell\.py.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1932 = /.{0,1000}scshellbof\.c.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1933 = /.{0,1000}scshellbof\.o.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1934 = /.{0,1000}scshellbofx64.{0,1000}/ nocase ascii wide
        // Description: Rapid Attack Infrastructure (RAI)
        // Reference: https://github.com/obscuritylabs/RAI
        $string1935 = /.{0,1000}searchsploit_rc.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string1936 = /.{0,1000}Seatbelt\.exe.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1937 = /.{0,1000}sec\-inject\s.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1938 = /.{0,1000}secinject\.cna.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1939 = /.{0,1000}secinject\.git.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1940 = /.{0,1000}secinject\.x64.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1941 = /.{0,1000}secinject\.x86.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1942 = /.{0,1000}secinject\/src.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1943 = /.{0,1000}secretsdump\..{0,1000}\.pyc.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string1944 = /.{0,1000}secretsdump\.py.{0,1000}/ nocase ascii wide
        // Description: Section Mapping Process Injection (secinject): Cobalt Strike BOF
        // Reference: https://github.com/apokryptein/secinject
        $string1945 = /.{0,1000}sec\-shinject\s.{0,1000}/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1946 = /.{0,1000}self_delete\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs
        // Reference: https://github.com/EspressoCake/Self_Deletion_BOF
        $string1947 = /.{0,1000}Self_Deletion_BOF.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string1948 = /.{0,1000}send_shellcode_via_pipe.{0,1000}/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string1949 = /.{0,1000}send_shellcode_via_pipe.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1950 = /.{0,1000}serverscan\.linux\.elf.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1951 = /.{0,1000}serverscan\.linux\.so.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1952 = /.{0,1000}serverScan\.win\.cna.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1953 = /.{0,1000}serverscan_386\.exe.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1954 = /.{0,1000}ServerScan_Air_.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1955 = /.{0,1000}ServerScan_Air_.{0,1000}_amd64.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1956 = /.{0,1000}ServerScan_Air_.{0,1000}_i386.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1957 = /.{0,1000}serverscan_air\-probes\.exe.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1958 = /.{0,1000}serverscan_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1959 = /.{0,1000}ServerScan_Pro_.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1960 = /.{0,1000}ServerScan_Pro_.{0,1000}_amd64.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1961 = /.{0,1000}ServerScan_Pro_.{0,1000}_i386.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1962 = /.{0,1000}serverscan64\s.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1963 = /.{0,1000}serverscan64\s.{0,1000}tcp.{0,1000}/ nocase ascii wide
        // Description: ServerScan is a high-concurrency network scanning and service detection tool developed in Golang.
        // Reference: https://github.com/Adminisme/ServerScan
        $string1964 = /.{0,1000}serverscan86\s.{0,1000}/ nocase ascii wide
        // Description: New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.
        // Reference: https://github.com/netero1010/ServiceMove-BOF
        $string1965 = /.{0,1000}servicemove.{0,1000}hid\.dll.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1966 = /.{0,1000}set\shosts_stage.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1967 = /.{0,1000}set\skeylogger.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1968 = /.{0,1000}set\sobfuscate\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1969 = /.{0,1000}set\spipename\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1970 = /.{0,1000}set\ssmartinject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string1971 = /.{0,1000}set\suserwx.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string1972 = /.{0,1000}setc_webshell.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1973 = /.{0,1000}setLoaderFlagZero.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1974 = /.{0,1000}setthreadcontext\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string1975 = /.{0,1000}setthreadcontext\.x86.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string1976 = /.{0,1000}setup_obfuscate_xor_key.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string1977 = /.{0,1000}setup_reflective_loader.{0,1000}/ nocase ascii wide
        // Description: dump lsass
        // Reference: https://github.com/seventeenman/CallBackDump
        $string1978 = /.{0,1000}seventeenman\/CallBackDump.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string1979 = /.{0,1000}ShadowUser\/scvhost\.exe.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1980 = /.{0,1000}Sharp\sCompile.{0,1000}/ nocase ascii wide
        // Description: .NET Assembly to Retrieve Outlook Calendar Details
        // Reference: https://github.com/OG-Sadpanda/SharpCalendar
        $string1981 = /.{0,1000}SharpCalendar\.exe.{0,1000}/ nocase ascii wide
        // Description: C# alternative to the linux cat command... Prints file contents to console. For use with Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpCat
        $string1982 = /.{0,1000}SharpCat\.exe.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1983 = /.{0,1000}sharpcompile.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1984 = /.{0,1000}sharpCompileHandler.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1985 = /.{0,1000}SharpCompileServer.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1986 = /.{0,1000}SharpCompileServer\.exe.{0,1000}/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1987 = /.{0,1000}SharpCradle.{0,1000}logonpasswords.{0,1000}/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string1988 = /.{0,1000}SharpCradle\.exe.{0,1000}/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string1989 = /.{0,1000}SharpEventLoader.{0,1000}/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string1990 = /.{0,1000}SharpEventPersist.{0,1000}/ nocase ascii wide
        // Description: Read Excel Spreadsheets (XLS/XLSX) using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpExcelibur
        $string1991 = /.{0,1000}SharpExcelibur.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1992 = /.{0,1000}sharp\-exec\s.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string1993 = /.{0,1000}sharp\-fexec\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1994 = /.{0,1000}SharpGen\.dll.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1995 = /.{0,1000}sharpgen\.enable_cache.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1996 = /.{0,1000}sharpgen\.py.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string1997 = /.{0,1000}sharpgen\.set_location.{0,1000}/ nocase ascii wide
        // Description: C# binary with embeded golang hack-browser-data
        // Reference: https://github.com/S3cur3Th1sSh1t/Sharp-HackBrowserData
        $string1998 = /.{0,1000}Sharp\-HackBrowserData.{0,1000}/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string1999 = /.{0,1000}SharpHound\.cna.{0,1000}/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2000 = /.{0,1000}SharpHound\.exe.{0,1000}/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2001 = /.{0,1000}SharpHound\.ps1.{0,1000}/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2002 = /.{0,1000}Sharphound2\..{0,1000}/ nocase ascii wide
        // Description: Aggressor scripts for use with Cobalt Strike 3.0+
        // Reference: https://github.com/C0axx/AggressorScripts
        $string2003 = /.{0,1000}Sharphound\-Aggressor.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2004 = /.{0,1000}SharpSCShell.{0,1000}/ nocase ascii wide
        // Description: SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
        // Reference: https://github.com/anthemtotheego/SharpCradle
        $string2005 = /.{0,1000}SharpSploitConsole_x.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike kit for Persistence
        // Reference: https://github.com/0xthirteen/StayKit
        $string2006 = /.{0,1000}SharpStay\.exe.{0,1000}/ nocase ascii wide
        // Description: Read the contents of DOCX files using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string2007 = /.{0,1000}SharpSword\.exe.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2008 = /.{0,1000}SharpZeroLogon.{0,1000}/ nocase ascii wide
        // Description: List/Read contents of Zip files (in memory and without extraction) using CobaltStrike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpZippo
        $string2009 = /.{0,1000}SharpZippo\.exe.{0,1000}/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string2010 = /.{0,1000}shell\.exe\s\-s\spayload\.txt.{0,1000}/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string2011 = /.{0,1000}Shellcode_encryption\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string2012 = /.{0,1000}shellcode_generator\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Generator
        // Reference: https://github.com/RCStep/CSSG
        $string2013 = /.{0,1000}shellcode_generator_help\.html.{0,1000}/ nocase ascii wide
        // Description: ShellCode_Loader - Msf&CobaltStrike Antivirus ShellCode loader. Shellcode_encryption - Antivirus Shellcode encryption generation tool. currently tested for Antivirus 360 & Huorong & Computer Manager & Windows Defender (other antivirus software not tested).
        // Reference: https://github.com/Axx8/ShellCode_Loader
        $string2014 = /.{0,1000}ShellCode_Loader\.py.{0,1000}/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2015 = /.{0,1000}shellcode20\.exe.{0,1000}/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2016 = /.{0,1000}shellcode30\.exe.{0,1000}/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2017 = /.{0,1000}shellcode35\.exe.{0,1000}/ nocase ascii wide
        // Description: python ShellCode Loader (Cobaltstrike&Metasploit)
        // Reference: https://github.com/OneHone/C--Shellcode
        $string2018 = /.{0,1000}shellcode40\.exe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2019 = /.{0,1000}shspawn\sx64\s.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2020 = /.{0,1000}shspawn\sx86\s.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2021 = /.{0,1000}SigFlip\.exe\s\-.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2022 = /.{0,1000}SigFlip\.WinTrustData.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2023 = /.{0,1000}SigInject\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2024 = /.{0,1000}Sigloader\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2025 = /.{0,1000}SigLoader\/sigloader\.c.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2026 = /.{0,1000}sigwhatever\.exe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string2027 = /.{0,1000}Silent\sLsass\sDump.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files
        // Reference: https://github.com/guervild/BOFs
        $string2028 = /.{0,1000}silentLsassDump.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2029 = /.{0,1000}\-Situational\-Awareness\-BOF.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2030 = /.{0,1000}sleep_python_bridge\.sleepy.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2031 = /.{0,1000}sleep_python_bridge\.striker.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2032 = /.{0,1000}sleepmask\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2033 = /.{0,1000}sleepmask\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2034 = /.{0,1000}sleepmask_pivot\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: This project is 'bridge' between the sleep and python language. It allows the control of a Cobalt Strike teamserver through python without the need for for the standard GUI client.
        // Reference: https://github.com/Cobalt-Strike/sleep_python_bridge
        $string2035 = /.{0,1000}sleepmask_pivot\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2036 = /.{0,1000}smb_pipename_stager.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2037 = /.{0,1000}smbattack\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2038 = /.{0,1000}smbrelayclient\.py.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2039 = /.{0,1000}smbrelayserver\..{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2040 = /.{0,1000}smtprelayclient\.py.{0,1000}/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2041 = /.{0,1000}socky\swhoami.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2042 = /.{0,1000}SourcePoint.{0,1000}Loader\.go.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2043 = /.{0,1000}source\-teamserver\.sh.{0,1000}/ nocase ascii wide
        // Description: CrossC2 developed based on the Cobalt Strike framework can be used for other cross-platform system control. CrossC2Kit provides some interfaces for users to call to manipulate the CrossC2 Beacon session. thereby extending the functionality of Cobalt Strike.
        // Reference: https://github.com/CrossC2/CrossC2Kit
        $string2044 = /.{0,1000}spawn\/runshellcode.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2045 = /.{0,1000}SpawnTheThing\(.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2046 = /.{0,1000}spawnto\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2047 = /.{0,1000}\'spawnto_x64\'.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2048 = /.{0,1000}\'spawnto_x86\'.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2049 = /.{0,1000}spoolss_\#\#.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2050 = /.{0,1000}spoolsystem\sinject.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2051 = /.{0,1000}spoolsystem\sspawn.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2052 = /.{0,1000}spoolsystem\.cna.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2053 = /.{0,1000}SpoolTrigger\.x64\.dl.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2054 = /.{0,1000}SpoolTrigger\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2055 = /.{0,1000}SpoolTrigger\.x86\.dl.{0,1000}/ nocase ascii wide
        // Description: Information released publicly by NCC Group's Full Spectrum Attack Simulation (FSAS) team
        // Reference: https://github.com/nccgroup/nccfsas
        $string2056 = /.{0,1000}SpoolTrigger\.x86\.dll.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2057 = /.{0,1000}SpoolTrigger\\SpoolTrigger\..{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2058 = /.{0,1000}Spray\-AD\s.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2059 = /.{0,1000}Spray\-AD\.cna.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2060 = /.{0,1000}Spray\-AD\.dll.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2061 = /.{0,1000}Spray\-AD\.exe.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2062 = /.{0,1000}Spray\-AD\.sln.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2063 = /.{0,1000}Spray\-AD\\Spray\-AD.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2064 = /.{0,1000}src\/Remote\/chromeKey\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2065 = /.{0,1000}src\/Remote\/lastpass\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2066 = /.{0,1000}src\/Remote\/sc_config\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2067 = /.{0,1000}src\/Remote\/sc_create\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2068 = /.{0,1000}src\/Remote\/sc_delete\/.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike injection BOFs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2069 = /.{0,1000}src\/Remote\/sc_start\/.{0,1000}/ nocase ascii wide
        // Description: A Cobalt Strike tool to audit Active Directory user accounts for weak - well known or easy guessable passwords.
        // Reference: https://github.com/outflanknl/Spray-AD
        $string2070 = /.{0,1000}Src\/Spray\-AD.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2071 = /.{0,1000}src\/zerologon\.c.{0,1000}/ nocase ascii wide
        // Description: Remove API hooks from a Beacon process.
        // Reference: https://github.com/rsmudge/unhook-bof
        $string2072 = /.{0,1000}src\\unhook\.c.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2073 = /.{0,1000}srvsvc_\#\#.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2074 = /.{0,1000}stage\.obfuscate.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2075 = /.{0,1000}stage_smartinject.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2076 = /.{0,1000}stage_transform_x64_prepend.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2077 = /.{0,1000}stage_transform_x64_strrep1.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2078 = /.{0,1000}stage_transform_x86_prepend.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike random C2 Profile generator
        // Reference: https://github.com/threatexpress/random_c2_profile
        $string2079 = /.{0,1000}stage_transform_x86_strrep1.{0,1000}/ nocase ascii wide
        // Description: CACTUSTORCH: Payload Generation for Adversary Simulations
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string2080 = /.{0,1000}stageless\spayload.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2081 = /.{0,1000}stager_bind_pipe.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2082 = /.{0,1000}stager_bind_pipe.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2083 = /.{0,1000}stager_bind_tcp.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2084 = /.{0,1000}stager_bind_tcp.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2085 = /.{0,1000}start\sstinger\s/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2086 = /.{0,1000}StartProcessFake\(.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2087 = /.{0,1000}static_syscalls_apc_spawn\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2088 = /.{0,1000}static_syscalls_apc_spawn.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2089 = /.{0,1000}static_syscalls_dump.{0,1000}/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2090 = /.{0,1000}StayKit\.cna.{0,1000}/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2091 = /.{0,1000}StayKit\.exe.{0,1000}/ nocase ascii wide
        // Description: StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2092 = /.{0,1000}StayKit\.git.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2093 = /.{0,1000}steal_token\(.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2094 = /.{0,1000}steal_token_access_mask.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2095 = /.{0,1000}stinger_client\s\-.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2096 = /.{0,1000}stinger_client\.py.{0,1000}/ nocase ascii wide
        // Description: Bypass firewall for traffic forwarding using webshell. Pystinger implements SOCK4 proxy and port mapping through webshell. It can be directly used by metasploit-framework - viper- cobalt strike for session online.
        // Reference: https://github.com/FunnyWolf/pystinger
        $string2097 = /.{0,1000}stinger_server\.exe.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2098 = /.{0,1000}strip_bof\.ps1.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2099 = /.{0,1000}strip\-bof\s\-Path\s.{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2100 = /.{0,1000}suspendresume\.x64\..{0,1000}/ nocase ascii wide
        // Description: Cobaltstrike Bofs
        // Reference: https://github.com/trustedsec/CS-Remote-OPs-BOF
        $string2101 = /.{0,1000}suspendresume\.x86\..{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2102 = /.{0,1000}SW2_GetSyscallNumber.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2103 = /.{0,1000}SW2_HashSyscall.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2104 = /.{0,1000}SW2_PopulateSyscallList.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2105 = /.{0,1000}SW2_RVA2VA.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2106 = /.{0,1000}SwampThing\.exe.{0,1000}/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2107 = /.{0,1000}SweetPotato\.cna.{0,1000}/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2108 = /.{0,1000}SweetPotato\.csproj.{0,1000}/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2109 = /.{0,1000}SweetPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2110 = /.{0,1000}SweetPotato\.ImpersonationToken.{0,1000}/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2111 = /.{0,1000}SweetPotato\.sln.{0,1000}/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2112 = /.{0,1000}syscall_disable_priv\s.{0,1000}/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2113 = /.{0,1000}syscall_enable_priv\s.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2114 = /.{0,1000}syscalls\.asm.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2115 = /.{0,1000}syscalls_dump\..{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2116 = /.{0,1000}syscalls_inject\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2117 = /.{0,1000}syscalls_inject\..{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2118 = /.{0,1000}syscalls_shinject\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2119 = /.{0,1000}syscalls_shspawn\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2120 = /.{0,1000}syscalls_spawn\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2121 = /.{0,1000}syscalls_spawn\..{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2122 = /.{0,1000}syscallsapcspawn\.x64.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2123 = /.{0,1000}syscalls\-asm\.h.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2124 = /.{0,1000}syscallsdump\.x64.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2125 = /.{0,1000}syscallsinject\.x64.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2126 = /.{0,1000}syscallsspawn\.x64.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2127 = /.{0,1000}SysWhispers\.git\s.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)
        // Reference: https://github.com/outflanknl/InlineWhispers
        $string2128 = /.{0,1000}syswhispers\.py.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2129 = /.{0,1000}syswhispers\.py.{0,1000}/ nocase ascii wide
        // Description: Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF) via Syswhispers2
        // Reference: https://github.com/Sh0ckFR/InlineWhispers2
        $string2130 = /.{0,1000}SysWhispers2.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2131 = /.{0,1000}TailorScan\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2132 = /.{0,1000}TailorScan_darwin.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2133 = /.{0,1000}TailorScan_freebsd.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2134 = /.{0,1000}TailorScan_linux_.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2135 = /.{0,1000}TailorScan_netbsd_.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2136 = /.{0,1000}TailorScan_openbsd_.{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2137 = /.{0,1000}TailorScan_windows_.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2138 = /.{0,1000}TaskShell\.exe\s.{0,1000}\s\-b\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: tamper scheduled task with a binary
        // Reference: https://github.com/RiccardoAncarani/TaskShell
        $string2139 = /.{0,1000}TaskShell\.exe\s.{0,1000}\s\-s\s.{0,1000}SYSTEM.{0,1000}/ nocase ascii wide
        // Description: A proof-of-concept Cobalt Strike Reflective Loader which aims to recreate. integrate. and enhance Cobalt Strike's evasion features!
        // Reference: https://github.com/boku7/BokuLoader
        $string2140 = /.{0,1000}teamserver.{0,1000}\sno_evasion\.profile.{0,1000}/ nocase ascii wide
        // Description: CobaltStrike4.4 one-click deployment script Randomly generate passwords. keys. port numbers. certificates. etc.. to solve the problem that cs4.x cannot run on Linux and report errors
        // Reference: https://github.com/AlphabugX/csOnvps
        $string2141 = /.{0,1000}TeamServer\.prop.{0,1000}/ nocase ascii wide
        // Description: LSASS memory dumper using direct system calls and API unhooking.
        // Reference: https://github.com/outflanknl/Dumpert/tree/master/Dumpert-Aggressor
        $string2142 = /.{0,1000}Temp\\dumpert.{0,1000}/ nocase ascii wide
        // Description: Load any Beacon Object File using Powershell!
        // Reference: https://github.com/airbus-cert/Invoke-Bof
        $string2143 = /.{0,1000}test_invoke_bof\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2144 = /.{0,1000}tgtdelegation\s.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2145 = /.{0,1000}tgtdelegation\.cna.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2146 = /.{0,1000}tgtdelegation\.x64.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2147 = /.{0,1000}tgtdelegation\.x86.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2148 = /.{0,1000}tgtParse\.py\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Python API
        // Reference: https://github.com/dcsync/pycobalt
        $string2149 = /.{0,1000}third_party\/SharpGen.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2150 = /.{0,1000}third\-party.{0,1000}winvnc.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/threatexpress/malleable-c2
        $string2151 = /.{0,1000}threatexpress.{0,1000}malleable.{0,1000}/ nocase ascii wide
        // Description: Convert Cobalt Strike profiles to modrewrite scripts
        // Reference: https://github.com/threatexpress/cs2modrewrite
        $string2152 = /.{0,1000}threatexpress\/cs2modrewrite.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2153 = /.{0,1000}ticketConverter\.py\s.{0,1000}\.ccache\s.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike (CS) Beacon Object File (BOF) foundation for kernel exploitation using CVE-2021-21551.
        // Reference: https://github.com/tijme/kernel-mii
        $string2154 = /.{0,1000}tijme\/kernel\-mii.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2155 = /.{0,1000}TikiLoader.{0,1000}Hollower.{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2156 = /.{0,1000}TikiLoader\..{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2157 = /.{0,1000}TikiLoader\..{0,1000}/ nocase ascii wide
        // Description: EDR Evasion - Combination of SwampThing - TikiTorch
        // Reference: https://github.com/rkervella/CarbonMonoxide
        $string2158 = /.{0,1000}TikiLoader\.dll.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2159 = /.{0,1000}TikiLoader\.dll.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2160 = /.{0,1000}TikiLoader\.Injector.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2161 = /.{0,1000}TikiLoader\\TikiLoader.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2162 = /.{0,1000}TikiSpawn\.dll.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2163 = /.{0,1000}TikiSpawn\.exe.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2164 = /.{0,1000}TikiSpawn\.ps1.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2165 = /.{0,1000}TikiSpawnAs.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2166 = /.{0,1000}TikiSpawnAsAdmin.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2167 = /.{0,1000}TikiSpawnElevated.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2168 = /.{0,1000}TikiSpawnWOppid.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2169 = /.{0,1000}TikiSpawnWppid.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2170 = /.{0,1000}TikiTorch\.exe.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2171 = /.{0,1000}TikiVader\..{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2172 = /.{0,1000}timwhitez\/Doge\-Loader.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2173 = /.{0,1000}Tmprovider\.dll.{0,1000}/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2174 = /.{0,1000}toggle_privileges\.cna.{0,1000}/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2175 = /.{0,1000}toggle_privileges_bof\..{0,1000}/ nocase ascii wide
        // Description: Syscall BOF to arbitrarily add/detract process token privilege rights.
        // Reference: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF
        $string2176 = /.{0,1000}Toggle_Token_Privileges_BOF.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2177 = /.{0,1000}ToggleWDigest.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string2178 = /.{0,1000}TokenStripBOF\/src.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2179 = /.{0,1000}token\-vault\ssteal.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2180 = /.{0,1000}token\-vault\.cna.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2181 = /.{0,1000}token\-vault\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2182 = /.{0,1000}token\-vault\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/MemReader_BoF
        $string2183 = /.{0,1000}trainr3kt\/MemReader_BoF.{0,1000}/ nocase ascii wide
        // Description: MemReader Beacon Object File will allow you to search and extract specific strings from a target process memory and return what is found to the beacon output
        // Reference: https://github.com/trainr3kt/Readfile_BoF
        $string2184 = /.{0,1000}trainr3kt\/Readfile_BoF.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving cmd.exe by using DCOM object.
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2185 = /.{0,1000}TrustedPath\-UACBypass\-BOF.{0,1000}/ nocase ascii wide
        // Description: Modified SweetPotato to work with CobaltStrike v4.0
        // Reference: https://github.com/Tycx2ry/SweetPotato_CS
        $string2186 = /.{0,1000}Tycx2ry\/SweetPotato.{0,1000}/ nocase ascii wide
        // Description: SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.
        // Reference: https://github.com/Tylous/SourcePoint
        $string2187 = /.{0,1000}Tylous\/SourcePoint.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2188 = /.{0,1000}UACBypass\-BOF.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2189 = /.{0,1000}uac\-schtasks\s.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2190 = /.{0,1000}uac\-schtasks.{0,1000}/ nocase ascii wide
        // Description: New UAC bypass for Silent Cleanup for CobaltStrike
        // Reference: https://github.com/EncodeGroup/UAC-SilentClean
        $string2191 = /.{0,1000}uac\-silentcleanup.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2192 = /.{0,1000}uac\-token\-duplication.{0,1000}/ nocase ascii wide
        // Description: SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing 
        // Reference: https://github.com/SpiderLabs/SharpCompile
        $string2193 = /.{0,1000}uhttpsharp\..{0,1000}/ nocase ascii wide
        // Description: Self-use suture monster intranet scanner - supports port scanning - identifying services - getting title - scanning multiple network cards - ms17010 scanning - icmp survival detection
        // Reference: https://github.com/uknowsec/TailorScan
        $string2194 = /.{0,1000}uknowsec\/TailorScan.{0,1000}/ nocase ascii wide
        // Description: Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x
        // Reference: https://github.com/rsmudge/Malleable-C2-Profiles
        $string2195 = /.{0,1000}UMJjAiNUUtvNww0lBj9tzWegwphuIn6hNP9eeIDfOrcHJ3nozYFPT\-Jl7WsmbmjZnQXUesoJkcJkpdYEdqgQFE6QZgjWVsLSSDonL28DYDVJ.{0,1000}/ nocase ascii wide
        // Description: Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2196 = /.{0,1000}Un1k0d3r\/SCShell.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Malleable C2 Design and Reference Guide
        // Reference: https://github.com/BC-SECURITY/Malleable-C2-Profiles
        $string2197 = /.{0,1000}ursnif_IcedID\.profile.{0,1000}/ nocase ascii wide
        // Description: A Visual Studio template used to create Cobalt Strike BOFs
        // Reference: https://github.com/securifybv/Visual-Studio-BOF-template
        $string2198 = /.{0,1000}Visual\-Studio\-BOF\-template.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2199 = /.{0,1000}vssenum\.x64\..{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2200 = /.{0,1000}vssenum\.x86\..{0,1000}/ nocase ascii wide
        // Description: Bloodhound Attack Path Automation in CobaltStrike
        // Reference: https://github.com/vysecurity/ANGRYPUPPY
        $string2201 = /.{0,1000}vysecurity\/ANGRYPUPPY.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File (BOF) to obtain a usable TGT for the current user and does not require elevated privileges on the host
        // Reference: https://github.com/connormcgarr/tgtdelegation
        $string2202 = /.{0,1000}wcfrelayserver\.py.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2203 = /.{0,1000}wdigest\!g_fParameter_UseLogonCredential.{0,1000}/ nocase ascii wide
        // Description: A Beacon Object File (BOF) for Cobalt Strike which uses direct system calls to enable WDigest credential caching.
        // Reference: https://github.com/outflanknl/WdToggle
        $string2204 = /.{0,1000}wdigest\!g_IsCredGuardEnabled.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2205 = /.{0,1000}whereami\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.
        // Reference: https://github.com/boku7/whereami
        $string2206 = /.{0,1000}whereami\.x64.{0,1000}/ nocase ascii wide
        // Description: Situational Awareness commands implemented using Beacon Object Files
        // Reference: https://github.com/trustedsec/CS-Situational-Awareness-BOF
        $string2207 = /.{0,1000}WhoamiGetTokenInfo.{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2208 = /.{0,1000}wifidump\.cna.{0,1000}/ nocase ascii wide
        // Description: Erebus CobaltStrike post penetration testing plugin
        // Reference: https://github.com/DeEpinGh0st/Erebus
        $string2209 = /.{0,1000}windows\-exploit\-suggester\..{0,1000}/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2210 = /.{0,1000}winrmdll\s.{0,1000}/ nocase ascii wide
        // Description: C++ WinRM API via Reflective DLL
        // Reference: https://github.com/mez-0/winrmdll
        $string2211 = /.{0,1000}winrmdll\..{0,1000}/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2212 = /.{0,1000}Winsocky\-main.{0,1000}/ nocase ascii wide
        // Description: Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing. The VNC protocol is not involved but the result is a similar experience. This Cobalt Strike BOF implementation was created as an alternative to TinyNuke/forks that are written in C++
        // Reference: https://github.com/WKL-Sec/HiddenDesktop
        $string2213 = /.{0,1000}WKL\-Sec\/HiddenDesktop.{0,1000}/ nocase ascii wide
        // Description: Winsocket for Cobalt Strike.
        // Reference: https://github.com/WKL-Sec/Winsocky
        $string2214 = /.{0,1000}WKL\-Sec\/Winsocky.{0,1000}/ nocase ascii wide
        // Description: A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls
        // Reference: https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
        $string2215 = /.{0,1000}wkssvc_\#\#.{0,1000}/ nocase ascii wide
        // Description: A CobaltStrike script that uses various WinAPIs to maintain permissions. including API setting system services. setting scheduled tasks. managing users. etc.
        // Reference: https://github.com/yanghaoi/CobaltStrike_CNA
        $string2216 = /.{0,1000}Wmi_Persistence\.ps1.{0,1000}/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2217 = /.{0,1000}wmi\-event\-lateral\-movement\..{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2218 = /.{0,1000}WMI\-EventSub\.cpp.{0,1000}/ nocase ascii wide
        // Description: LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript
        // Reference: https://github.com/RiccardoAncarani/LiquidSnake
        $string2219 = /.{0,1000}wmi\-lateral\-movement\..{0,1000}/ nocase ascii wide
        // Description: Collection of beacon BOF written to learn windows and cobaltstrike
        // Reference: https://github.com/Yaxser/CobaltStrike-BOF
        $string2220 = /.{0,1000}WMI\-ProcessCreate\.cpp.{0,1000}/ nocase ascii wide
        // Description: generate CobaltStrike's cross-platform payload
        // Reference: https://github.com/gloxec/CrossC2
        $string2221 = /.{0,1000}write_cs_teamserver.{0,1000}/ nocase ascii wide
        // Description: TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process. allocates a region of memory. writes shellcode into that region. and then uses CreateRemoteThread to execute said shellcode. Both the process and shellcode are specified by the user. The primary use case is as a JavaScript/VBScript loader via DotNetToJScript. which can be utilised in a variety of payload types such as HTA and VBA.
        // Reference: https://github.com/rasta-mouse/TikiTorch
        $string2222 = /.{0,1000}WriteAndExecuteShellcode.{0,1000}/ nocase ascii wide
        // Description: A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.
        // Reference: https://github.com/EspressoCake/PPLDump_BOF
        $string2223 = /.{0,1000}WritePayloadDllTransacted.{0,1000}/ nocase ascii wide
        // Description: The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
        // Reference: https://github.com/rsmudge/ElevateKit
        $string2224 = /.{0,1000}wscript_elevator.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOFs) for shells and lols
        // Reference: https://github.com/RiccardoAncarani/BOFs
        $string2225 = /.{0,1000}wts_enum_remote_processes.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Beacon Object Files (BOFs) written in rust with rust core and alloc.
        // Reference: https://github.com/wumb0/rust_bof
        $string2226 = /.{0,1000}wumb0\/rust_bof.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
        // Reference: https://github.com/xforcered/CredBandit
        $string2227 = /.{0,1000}xforcered\/CredBandit.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/xforcered/Detect-Hooks
        $string2228 = /.{0,1000}xforcered\/Detect\-Hooks.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike Shellcode Loader by Golang
        // Reference: https://github.com/timwhitez/Doge-Loader
        $string2229 = /.{0,1000}xor\.exe\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: A simple python packer to easily bypass Windows Defender
        // Reference: https://github.com/Unknow101/FuckThatPacker
        $string2230 = /.{0,1000}xor_payload.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2231 = /.{0,1000}xpipe\s\\\\.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2232 = /.{0,1000}xpipe.{0,1000}lsass.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2233 = /.{0,1000}xpipe\.c.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2234 = /.{0,1000}xpipe\.cna.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions
        // Reference: https://github.com/boku7/xPipe
        $string2235 = /.{0,1000}xpipe\.o.{0,1000}/ nocase ascii wide
        // Description: A cobaltstrike shellcode loader - past domestic mainstream antivirus software
        // Reference: https://github.com/YDHCUI/csload.net
        $string2236 = /.{0,1000}YDHCUI\/csload\.net.{0,1000}/ nocase ascii wide
        // Description: Chinese clone of cobaltstrike
        // Reference: https://github.com/YDHCUI/manjusaka
        $string2237 = /.{0,1000}YDHCUI\/manjusaka.{0,1000}/ nocase ascii wide
        // Description: Example code for using named pipe output with beacon ReflectiveDLLs
        // Reference: https://github.com/rxwx/cs-rdll-ipc-example
        $string2238 = /.{0,1000}youcantpatchthis.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2239 = /.{0,1000}ysoserial\.exe.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2240 = /.{0,1000}YwBhAGwAYwA\=.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2241 = /.{0,1000}zerologon\.x64.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2242 = /.{0,1000}zerologon\.x86.{0,1000}/ nocase ascii wide
        // Description: Cobalt Strike BOF zerologon exploit
        // Reference: https://github.com/rsmudge/ZeroLogon-BOF
        $string2243 = /.{0,1000}ZeroLogon\-BOF.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2244 = /.{0,1000}zha0gongz1.{0,1000}/ nocase ascii wide
        // Description: Implement load Cobalt Strike & Metasploit&Sliver shellcode with golang
        // Reference: https://github.com/zha0gongz1/DesertFox
        $string2245 = /.{0,1000}zha0gongz1\/DesertFox.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2246 = /.{0,1000}ziiiiizzzb.{0,1000}/ nocase ascii wide
        // Description: InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module
        // Reference: https://github.com/anthemtotheego/InlineExecute-Assembly
        $string2247 = /.{0,1000}ziiiiizzzib.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2248 = /\\\\demoagent_11/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2249 = /\\\\demoagent_22/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2250 = /\\\\DserNamePipe.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2251 = /\\\\f4c3.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2252 = /\\\\f53f.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2253 = /\\\\fullduplex_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2254 = /\\\\interprocess_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2255 = /\\\\lsarpc_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2256 = /\\\\mojo_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2257 = /\\\\msagent_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2258 = /\\\\MsFteWds.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2259 = /\\\\msrpc_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2260 = /\\\\MSSE\-.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2261 = /\\\\mypipe\-.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2262 = /\\\\netlogon_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2263 = /\\\\ntsvcs.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2264 = /\\\\PGMessagePipe.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2265 = /\\\\postex_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2266 = /\\\\postex_ssh_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2267 = /\\\\samr_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2268 = /\\\\scerpc_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2269 = /\\\\SearchTextHarvester.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2270 = /\\\\spoolss_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2271 = /\\\\srvsvc_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2272 = /\\\\status_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2273 = /\\\\UIA_PIPE.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2274 = /\\\\win\\msrpc_.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2275 = /\\\\winsock.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2276 = /\\\\Winsock2\\CatalogChangeListener\-.{0,1000}/ nocase ascii wide
        // Description: pipe names - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2277 = /\\\\wkssvc_.{0,1000}/ nocase ascii wide
        // Description: Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR
        // Reference: https://github.com/anthemtotheego/Detect-Hooks
        $string2278 = /detect\-hooks/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2279 = /doc\.1a\..{0,1000}\\\..{0,1000}/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2280 = /doc\.4a\..{0,1000}\\\..{0,1000}/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2281 = /doc\.bc\..{0,1000}\\\..{0,1000}/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2282 = /doc\.md\..{0,1000}\\\..{0,1000}/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2283 = /doc\.po\..{0,1000}\\\..{0,1000}/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2284 = /doc\.tx\..{0,1000}\\\..{0,1000}/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2285 = /doc\-stg\-prepend.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: dns beacons - Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2286 = /doc\-stg\-sh.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Various Cobalt Strike BOFs
        // Reference: https://github.com/rvrsh3ll/BOF_Collection
        $string2287 = /dumpwifi\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files
        // Reference: https://github.com/ajpc500/BOFs
        $string2288 = /etw\sstop/ nocase ascii wide
        // Description: Beacon Object File implementation of Event Viewer deserialization UAC bypass
        // Reference: https://github.com/netero1010/TrustedPath-UACBypass-BOF
        $string2289 = /EVUAC\s.{0,1000}/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2290 = /fw_walk\sdisplay.{0,1000}/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2291 = /fw_walk\sstatus.{0,1000}/ nocase ascii wide
        // Description: A BOF to interact with COM objects associated with the Windows software firewall.
        // Reference: https://github.com/EspressoCake/Firewall_Walker_BOF
        $string2292 = /fw_walk\stotal.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2293 = /get\-delegation\s.{0,1000}/ nocase ascii wide
        // Description: This tool uses LDAP to check a domain for known abusable Kerberos delegation settings
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string2294 = /get\-spns\s.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string2295 = /koh\sexit.{0,1000}/ nocase ascii wide
        // Description: Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // Reference: https://github.com/GhostPack/Koh
        $string2296 = /koh\slist.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2297 = /Ladon\s.{0,1000}\-.{0,1000}\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2298 = /Ladon\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2299 = /Ladon\s.{0,1000}\/.{0,1000}\s.{0,1000}/ nocase ascii wide
        // Description: Ladon is a large-scale intranet penetration tool. which can be modularized by PowerShell. plugged in CS. loaded in memory and has no file scanning
        // Reference: https://github.com/k8gege/Ladon
        $string2300 = /Ladon\sMac\s.{0,1000}\s/ nocase ascii wide
        // Description: Beacon Object File & C# project to check LDAP signing
        // Reference: https://github.com/cube0x0/LdapSignCheck
        $string2301 = /LdapSignCheck\s.{0,1000}/ nocase ascii wide
        // Description: Adversary Simulations and Red Team Operations are security assessments that replicate the tactics and techniques of an advanced adversary in a network
        // Reference: https://www.cobaltstrike.com/
        $string2302 = /load\s.{0,1000}\.cna/ nocase ascii wide
        // Description: A basic implementation of abusing the SeBackupPrivilege via Remote Registry dumping to dump the remote SAM SECURITY AND SYSTEM hives.
        // Reference: https://github.com/m57/cobaltstrike_bofs
        $string2303 = /make_token\s.{0,1000}/ nocase ascii wide
        // Description: Strstr with user-supplied needle and filename as a BOF.
        // Reference: https://github.com/EspressoCake/Needle_Sift_BOF
        $string2304 = /needle_sift\s.{0,1000}/ nocase ascii wide
        // Description: Collection of CobaltStrike beacon object files
        // Reference: https://github.com/pwn1sher/CS-BOFs
        $string2305 = /remotereg\s.{0,1000}/ nocase ascii wide
        // Description: Spectrum Attack Simulation beacons
        // Reference: https://github.com/nccgroup/nccfsas/
        $string2306 = /rev2self.{0,1000}/ nocase ascii wide
        // Description: BypassAV ShellCode Loader (Cobaltstrike/Metasploit)
        // Reference: https://github.com/k8gege/scrun
        $string2307 = /scrun\.exe\s.{0,1000}/ nocase ascii wide
        // Description: bypassAV cobaltstrike shellcode
        // Reference: https://github.com/jas502n/bypassAV-1
        $string2308 = /shell\.exe\s\-u\shttp:\/\/.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string2309 = /SigFlip\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
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
        $string2313 = /spawn\s.{0,1000}\.exe\s.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: Beacon Object File to delete token privileges and lower the integrity level to untrusted for a specified process
        // Reference: https://github.com/nick-frischkorn/TokenStripBOF
        $string2314 = /TokenStrip\s.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2315 = /token\-vault\screate.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2316 = /token\-vault\sremove.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2317 = /token\-vault\sset\s.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2318 = /token\-vault\sshow.{0,1000}/ nocase ascii wide
        // Description: In-memory token vault BOF for Cobalt Strike
        // Reference: https://github.com/Henkru/cs-token-vault
        $string2319 = /token\-vault\suse.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
