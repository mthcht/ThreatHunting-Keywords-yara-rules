
rule GUID_Detection
{
    meta:
        author = "@mthcht"
        description = "Detects GUIDs of offensive tools - taken from https://github.com/BADGUIDS/badguids.github.io"
    
    strings:
        // A windows token impersonation tool
        // https://github.com/sensepost/impersonate
        $guid_00630066_0B43_474E_A93B_417CF1A65195 = "00630066-0B43-474E-A93B-417CF1A65195" nocase

        // Cross-platform multi-protocol VPN software abused by attackers
        // https://github.com/SoftEtherVPN/SoftEtherVPN
        $guid_00B41CF0_7AE9_4542_9970_77B312412535 = "00B41CF0-7AE9-4542-9970-77B312412535" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_00D7268A_92A9_4CD4_ADDF_175E9BF16AE0 = "00D7268A-92A9-4CD4-ADDF-175E9BF16AE0" nocase

        // Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // https://github.com/securesean/DecryptAutoLogon
        $guid_015A37FC_53D0_499B_BFFE_AB88C5086040 = "015A37FC-53D0-499B-BFFE-AB88C5086040" nocase

        // Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // https://github.com/dirkjanm/ROADtoken
        $guid_018BD6D4_9019_42FD_8D3A_831B23B47CB2 = "018BD6D4-9019-42FD-8D3A-831B23B47CB2" nocase

        // StandIn is a small .NET35/45 AD post-exploitation toolkit
        // https://github.com/FuzzySecurity/StandIn
        $guid_01C142BA_7AF1_48D6_B185_81147A2F7DB7 = "01C142BA-7AF1-48D6-B185-81147A2F7DB7" nocase

        // remotely killing EDR with WDAC
        // https://github.com/logangoins/Krueger
        $guid_022E5A85_D732_4C5D_8CAD_A367139068D8 = "022E5A85-D732-4C5D-8CAD-A367139068D8" nocase

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_023B2DB0_6DA4_4F0D_988B_4D9BF522DA37 = "023B2DB0-6DA4-4F0D-988B-4D9BF522DA37" nocase

        // A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // https://github.com/INotGreen/SharpThief
        $guid_025280A3_24F7_4C55_9B5E_D08124A52546 = "025280A3-24F7-4C55-9B5E-D08124A52546" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_027FAC75_3FDB_4044_8DD0_BC297BD4C461 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_027FAC75_3FDB_4044_8DD0_BC297BD4C461 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_027FAC75_3FDB_4044_8DD0_BC297BD4C461 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_027FAC75_3FDB_4044_8DD0_BC297BD4C461 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_027FAC75_3FDB_4044_8DD0_BC297BD4C461 = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" nocase

        // Injects a DLL into a suspended process running as SYSTEM via the OfficeClickToRun service for privilege escalation - Shim Injector: Injects a DLL into a process by modifying shim data in memory without creating or registering new SDB files to evade detection.
        // https://github.com/deepinstinct/ShimMe
        $guid_0286bd5f_1a56_4251_8758_adb0338d4e98 = "0286bd5f-1a56-4251-8758-adb0338d4e98" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_02948DD6_47BD_4C82_9B4B_78931DB23B8A = "02948DD6-47BD-4C82-9B4B-78931DB23B8A" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_02EF15C0_BA19_4115_BB7F_F5B04F7087FE = "02EF15C0-BA19-4115-BB7F-F5B04F7087FE" nocase

        // automate abuse of clickonce applications
        // https://github.com/trustedsec/The_Shelf
        $guid_02FAF312_BF2A_466B_8AD2_1339A31C303B = "02FAF312-BF2A-466B-8AD2-1339A31C303B" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_034B1C28_96B9_486A_B238_9C651EAA32CA = "034B1C28-96B9-486A-B238-9C651EAA32CA" nocase

        // SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // https://github.com/Mayyhem/SharpSCCM/
        $guid_03652836_898E_4A9F_B781_B7D86E750F60 = "03652836-898E-4A9F-B781-B7D86E750F60" nocase

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_03A09084_0576_45C5_97CA_B83B1A8688B8 = "03A09084-0576-45C5-97CA-B83B1A8688B8" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_043EE329_C00A_4F67_971F_BF1C55D4BC1A = "043EE329-C00A-4F67-971F-BF1C55D4BC1A" nocase

        // unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $guid_0472A393_9503_491D_B6DA_FA47CD567EDE = "0472A393-9503-491D-B6DA-FA47CD567EDE" nocase

        // EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // https://github.com/wavestone-cdt/EDRSandblast
        $guid_04DFB6E4_809E_4C35_88A1_2CC5F1EBFEBD = "04DFB6E4-809E-4C35-88A1-2CC5F1EBFEBD" nocase

        // Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // https://github.com/gabriellandau/EDRSandblast-GodFault
        $guid_04DFB6E4_809E_4C35_88A1_2CC5F1EBFEBD = "04DFB6E4-809E-4C35-88A1-2CC5F1EBFEBD" nocase

        // Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // https://github.com/daem0nc0re/PrivFu
        $guid_04FC654C_D89A_44F9_9E34_6D95CE152E9D = "04FC654C-D89A-44F9-9E34-6D95CE152E9D" nocase

        // Windows Privilege Escalation Exploit BadPotato
        // https://github.com/BeichenDream/BadPotato
        $guid_0527a14f_1591_4d94_943e_d6d784a50549 = "0527a14f-1591-4d94-943e-d6d784a50549" nocase

        // RevengeRAT - AsyncRAT  Simple RAT
        // https://github.com/NYAN-x-CAT/RevengeRAT-Stub-Cssharp
        $guid_052C26C0_7979_4555_89CE_34C5CE8D8B34 = "052C26C0-7979-4555-89CE-34C5CE8D8B34" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_055BC73F_FCAE_4361_B035_2E156A101EA9 = "055BC73F-FCAE-4361-B035-2E156A101EA9" nocase

        // Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // https://github.com/XaFF-XaFF/Cronos-Rootkit
        $guid_05B4EB7F_3D59_4E6A_A7BC_7C1241578CA7 = "05B4EB7F-3D59-4E6A-A7BC-7C1241578CA7" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_06AF1D64_F2FC_4767_8794_7313C7BB0A40 = "06AF1D64-F2FC-4767-8794-7313C7BB0A40" nocase

        // *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // https://github.com/logangoins/Cable
        $guid_06B2AE2B_7FD3_4C36_B825_1594752B1D7B = "06B2AE2B-7FD3-4C36-B825-1594752B1D7B" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_06B2B14A_CE87_41C0_A77A_2644FE3231C7 = "06B2B14A-CE87-41C0-A77A-2644FE3231C7" nocase

        // .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // https://github.com/notdodo/LocalAdminSharp
        $guid_07628592_5A22_4C0A_9330_6C90BD7A94B6 = "07628592-5A22-4C0A-9330-6C90BD7A94B6" nocase

        // Terminate AV/EDR leveraging BYOVD attack
        // https://github.com/dmcxblue/SharpBlackout
        $guid_07DFC5AA_5B1F_4CCC_A3D3_816ECCBB6CB6 = "07DFC5AA-5B1F-4CCC-A3D3-816ECCBB6CB6" nocase

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_07EF7652_1C2D_478B_BB4B_F9560695A387 = "07EF7652-1C2D-478B-BB4B-F9560695A387" nocase

        // Metasploit is a widely-used. open-source framework designed for penetration testing. vulnerability assessment. and exploit development. It provides security professionals and researchers with a comprehensive platform to discover. exploit. and validate vulnerabilities in computer systems and networks. Metasploit includes a large database of pre-built exploits. payloads. and auxiliary modules that can be used to test various attack vectors. identify security weaknesses. and simulate real-world cyberattacks. By utilizing Metasploit. security teams can better understand potential threats and improve their overall security posture.
        // https://github.com/rapid7/metasploit-omnibus
        $guid_080A880D_BA94_4CF8_9015_5B2063073E02 = "080A880D-BA94-4CF8-9015-5B2063073E02" nocase

        // An open-source windows defender manager. Now you can disable windows defender permanently
        // https://github.com/pgkt04/defender-control
        $guid_089CA7D6_3277_4998_86AF_F6413290A442 = "089CA7D6-3277-4998-86AF-F6413290A442" nocase

        // Extract Windows Defender database from vdm files and unpack it
        // https://github.com/hfiref0x/WDExtract/
        $guid_08AEC00F_42ED_4E62_AE8D_0BFCE30A3F57 = "08AEC00F-42ED-4E62-AE8D-0BFCE30A3F57" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_08DBC2BF_E9F3_4AE4_B0CC_6E9C8767982D = "08DBC2BF-E9F3-4AE4-B0CC-6E9C8767982D" nocase

        // COM-hunter is a COM Hijacking persistnce tool written in C#
        // https://github.com/nickvourd/COM-Hunter
        $guid_09323E4D_BE0F_452A_9CA8_B07D2CFA9804 = "09323E4D-BE0F-452A-9CA8-B07D2CFA9804" nocase

        // From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // https://github.com/mpgn/BackupOperatorToDA
        $guid_0971A047_A45A_43F4_B7D8_16AC1114B524 = "0971A047-A45A-43F4-B7D8-16AC1114B524" nocase

        // A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // https://github.com/ShorSec/DllNotificationInjection
        $guid_0A1C2C46_33F7_4D4C_B8C6_1FC9B116A6DF = "0A1C2C46-33F7-4D4C-B8C6-1FC9B116A6DF" nocase

        // erase specified records from Windows event logs
        // https://github.com/QAX-A-Team/EventCleaner
        $guid_0A2B3F8A_EDC2_48B5_A5FC_DE2AC57C8990 = "0A2B3F8A-EDC2-48B5-A5FC-DE2AC57C8990" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_0A78E156_D03F_4667_B70E_4E9B4AA1D491 = "0A78E156-D03F-4667-B70E-4E9B4AA1D491" nocase

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_0ABB9F2A_6913_4174_9431_851F9D3E94B4 = "0ABB9F2A-6913-4174-9431-851F9D3E94B4" nocase

        // Manipulating and Abusing Windows Access Tokens
        // https://github.com/S1ckB0y1337/TokenPlayer
        $guid_0ADFD1F0_7C15_4A22_87B4_F67E046ECD96 = "0ADFD1F0-7C15-4A22-87B4-F67E046ECD96" nocase

        // The OpenBullet web testing application.
        // https://github.com/openbullet/openbullet
        $guid_0B6D8B01_861E_4CAF_B1C9_6670884381DB = "0B6D8B01-861E-4CAF-B1C9-6670884381DB" nocase

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_0BD5DE6B_8DA5_4CF1_AE53_A265010F52AA = "0BD5DE6B-8DA5-4CF1-AE53-A265010F52AA" nocase

        // Extracts passwords from a KeePass 2.x database directly from memory
        // https://github.com/denandz/KeeFarce
        $guid_0C3EB2F7_92BA_4895_99FC_7098A16FFE8C = "0C3EB2F7-92BA-4895-99FC-7098A16FFE8C" nocase

        // Dump cookies directly from Chrome process memory
        // https://github.com/Meckazin/ChromeKatz
        $guid_0C81C7D4_736A_4876_A36E_15E5B2EF5117 = "0C81C7D4-736A-4876-A36E-15E5B2EF5117" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_0C89EC7D_AC60_4591_8F6B_CB5F20EC0D8D = "0C89EC7D-AC60-4591-8F6B-CB5F20EC0D8D" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_0C8F49D8_BD68_420A_907D_031B83737C50 = "0C8F49D8-BD68-420A-907D-031B83737C50" nocase

        // ArtsOfGetSystem privesc tools
        // https://github.com/daem0nc0re/PrivFu/
        $guid_0CC923FB_E1FD_456B_9FE4_9EBA5A3DC2FC = "0CC923FB-E1FD-456B-9FE4-9EBA5A3DC2FC" nocase

        // PrintNightmare exploitation
        // https://github.com/outflanknl/PrintNightmare
        $guid_0CD16C7B_2A65_44E5_AB74_843BD23241D3 = "0CD16C7B-2A65-44E5-AB74-843BD23241D3" nocase

        // Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // https://github.com/zer0condition/mhydeath
        $guid_0D17A4B4_A7C4_49C0_99E3_B856F9F3B271 = "0D17A4B4-A7C4-49C0-99E3-B856F9F3B271" nocase

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_0DD419E5_D7B3_4360_874E_5838A7519355 = "0DD419E5-D7B3-4360-874E-5838A7519355" nocase

        // Open-Source Remote Administration Tool For Windows C# (RAT)
        // https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $guid_0DE8DA5D_061D_4649_8A56_48729CF1F789 = "0DE8DA5D-061D-4649-8A56-48729CF1F789" nocase

        // Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // https://github.com/CCob/Volumiser
        $guid_0DF38AD4_60AF_4F93_9C7A_7FB7BA692017 = "0DF38AD4-60AF-4F93-9C7A-7FB7BA692017" nocase

        // Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // https://github.com/ricardojoserf/NativeDump
        $guid_0DF612AE_47D8_422C_B0C5_0727EA60784F = "0DF612AE-47D8-422C-B0C5-0727EA60784F" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_0E423DD6_FAAF_4A66_8828_6A5A5F22269B = "0E423DD6-FAAF-4A66-8828-6A5A5F22269B" nocase

        // EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // https://github.com/Mattiwatti/EfiGuard
        $guid_0E4BAB8F_E6E0_47A8_8E99_8D451839967E = "0E4BAB8F-E6E0-47A8-8E99-8D451839967E" nocase

        // active directory weakness scan Vulnerability scanner
        // https://github.com/netwrix/pingcastle
        $guid_0E5D043A_CAA1_40C7_A616_773F347FA43F = "0E5D043A-CAA1-40C7-A616-773F347FA43F" nocase

        // A New Exploitation Technique for Visual Studio Projects
        // https://github.com/cjm00n/EvilSln
        $guid_0FE0D049_F352_477D_BCCD_ACBF7D4F6F15 = "0FE0D049-F352-477D-BCCD-ACBF7D4F6F15" nocase

        // Windows Local Privilege Escalation from Service Account to System
        // https://github.com/antonioCoco/RoguePotato
        $guid_105C2C6D_1C0A_4535_A231_80E355EFB112 = "105C2C6D-1C0A-4535-A231-80E355EFB112" nocase

        // A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // https://github.com/cybersectroll/SharpPersistSD
        $guid_107EBC1B_0273_4B3D_B676_DE64B7F52B33 = "107EBC1B-0273-4B3D-B676-DE64B7F52B33" nocase

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_10CC4D5B_DC87_4AEB_887B_E47367BF656B = "10CC4D5B-DC87-4AEB-887B-E47367BF656B" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_111BB935_2A0A_4AE2_AEB0_EF2FAA529840 = "111BB935-2A0A-4AE2-AEB0-EF2FAA529840" nocase

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_11385CC1_54B7_4968_9052_DF8BB1961F1E = "11385CC1-54B7-4968-9052-DF8BB1961F1E" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_116472CE_3924_40EA_90F9_50A1A00D0EC5 = "116472CE-3924-40EA-90F9-50A1A00D0EC5" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_1250BAE1_D26F_4EF2_9452_9B5009568336 = "1250BAE1-D26F-4EF2-9452-9B5009568336" nocase

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_128C450F_C8B3_403A_9D0C_E5AD6B7F566F = "128C450F-C8B3-403A-9D0C-E5AD6B7F566F" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_13431429_2DB6_480F_B73F_CA019FE759E3 = "13431429-2DB6-480F-B73F-CA019FE759E3" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_13A59BB8_0246_4FFA_951B_89B9A341F159 = "13A59BB8-0246-4FFA-951B-89B9A341F159" nocase

        // Nidhogg is an all-in-one simple to use rootkit for red teams.
        // https://github.com/Idov31/Nidhogg
        $guid_13C57810_FF18_4258_ABC9_935040A54F0B = "13C57810-FF18-4258-ABC9-935040A54F0B" nocase

        // SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // https://github.com/grayhatkiller/SharpExShell
        $guid_13C84182_2F5F_4EE8_A37A_4483E7E57154 = "13C84182-2F5F-4EE8-A37A-4483E7E57154" nocase

        // XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // https://github.com/FSecureLABS/Xrulez
        $guid_14083A04_DD4B_4E7D_A16E_86947D3D6D74 = "14083A04-DD4B-4E7D-A16E-86947D3D6D74" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_14CA405B_8BAC_48AB_9FBA_8FB5DF88FD0D = "14CA405B-8BAC-48AB-9FBA-8FB5DF88FD0D" nocase

        // Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // https://github.com/quasar/Quasar
        $guid_14CA405B_8BAC_48AB_9FBA_8FB5DF88FD0D = "14CA405B-8BAC-48AB-9FBA-8FB5DF88FD0D" nocase

        // Injects a DLL into a suspended process running as SYSTEM via the OfficeClickToRun service for privilege escalation - Shim Injector: Injects a DLL into a process by modifying shim data in memory without creating or registering new SDB files to evade detection.
        // https://github.com/deepinstinct/ShimMe
        $guid_1605d453_7d62_4198_a436_27e48ef828eb = "1605d453-7d62-4198-a436-27e48ef828eb" nocase

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_1617117C_0E94_4E6A_922C_836D616EC1F5 = "1617117C-0E94-4E6A-922C-836D616EC1F5" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_1659E645_27B0_4AB9_A10E_64BA4B801CB0 = "1659E645-27B0-4AB9-A10E-64BA4B801CB0" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_171A9A71_EDEF_4891_9828_44434A00585E = "171A9A71-EDEF-4891-9828-44434A00585E" nocase

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_17332F12_D796_42D1_9A3E_460590A49382 = "17332F12-D796-42D1-9A3E-460590A49382" nocase

        // Extracts passwords from a KeePass 2.x database directly from memory
        // https://github.com/denandz/KeeFarce
        $guid_17589EA6_FCC9_44BB_92AD_D5B3EEA6AF03 = "17589EA6-FCC9-44BB-92AD-D5B3EEA6AF03" nocase

        // mimikatz UUID
        // https://github.com/gentilkiwi/mimikatz
        $guid_17FC11E9_C258_4B8D_8D07_2F4125156244 = "17FC11E9-C258-4B8D-8D07-2F4125156244" nocase

        // Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // https://github.com/RowTeam/SharpDecryptPwd
        $guid_1824ED63_BE4D_4306_919D_9C749C1AE271 = "1824ED63-BE4D-4306-919D-9C749C1AE271" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_189219A1_9A2A_4B09_8F69_6207E9996F94 = "189219A1-9A2A-4B09-8F69-6207E9996F94" nocase

        // Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // https://github.com/OmerYa/Invisi-Shell
        $guid_18A66118_B98D_4FFC_AABE_DAFF5779F14C = "18A66118-B98D-4FFC-AABE-DAFF5779F14C" nocase

        // proof-of-concept of Process Forking.
        // https://github.com/D4stiny/ForkPlayground
        $guid_18C681A2_072F_49D5_9DE6_74C979EAE08B = "18C681A2-072F-49D5-9DE6-74C979EAE08B" nocase

        // C++ stealer (passwords - cookies - forms - cards - wallets) 
        // https://github.com/SecUser1/PredatorTheStealer
        $guid_190DFAEB_0288_4043_BE0E_3273FA653B52 = "190DFAEB-0288-4043-BE0E-3273FA653B52" nocase

        // DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // https://github.com/dafthack/DomainPasswordSpray
        $guid_1a3c4069_8c11_4336_bef8_9a43c0ba60e2 = "1a3c4069-8c11-4336-bef8-9a43c0ba60e2" nocase

        // registry manipulation to create scheduled tasks without triggering the usual event logs.
        // https://github.com/dmcxblue/SharpGhostTask
        $guid_1A8C9BD8_1800_46B0_8E22_7D3823C68366 = "1A8C9BD8-1800-46B0-8E22-7D3823C68366" nocase

        // Proof of concept code for thread pool based process injection in Windows.
        // https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $guid_1AFD1BA3_028A_4E0F_82A8_095F38694ECF = "1AFD1BA3-028A-4E0F-82A8-095F38694ECF" nocase

        // Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // https://github.com/itm4n/Perfusion
        $guid_1B1F64B3_B8A4_4BBB_BB66_F020E2D4F288 = "1B1F64B3-B8A4-4BBB-BB66-F020E2D4F288" nocase

        // The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // https://github.com/decoder-it/LocalPotato
        $guid_1B3C96A3_F698_472B_B786_6FED7A205159 = "1B3C96A3-F698-472B-B786-6FED7A205159" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_1B52A3D9_014C_4CBF_BB98_09080D9A8D16 = "1B52A3D9-014C-4CBF-BB98-09080D9A8D16" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_1BA54A13_B390_47B3_9628_B58A2BBA193B = "1BA54A13-B390-47B3-9628-B58A2BBA193B" nocase

        // Proof-of-Concept for CVE-2023-38146
        // https://github.com/gabe-k/themebleed
        $guid_1BACEDDC_CD87_41DC_948C_1C12F960BECB = "1BACEDDC-CD87-41DC-948C-1C12F960BECB" nocase

        // Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // https://github.com/CCob/SweetPotato
        $guid_1BF9C10F_6F89_4520_9D2E_AAF17D17BA5E = "1BF9C10F-6F89-4520-9D2E-AAF17D17BA5E" nocase

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_1c50adeb_53ac_41b9_9c34_7045cffbae45 = "1c50adeb-53ac-41b9-9c34-7045cffbae45" nocase

        // unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $guid_1C5EDA8C_D27F_44A4_A156_6F863477194D = "1C5EDA8C-D27F-44A4-A156-6F863477194D" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_1CC6E8A9_1875_430C_B2BB_F227ACD711B1 = "1CC6E8A9-1875-430C-B2BB-F227ACD711B1" nocase

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_1D1B59D9_10AF_40FE_BE99_578C09DB7A2A = "1D1B59D9-10AF-40FE-BE99-578C09DB7A2A" nocase

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_1DFC488D_E104_4F35_98DA_F23BF6D3F9DC = "1DFC488D-E104-4F35-98DA-F23BF6D3F9DC" nocase

        // Retrieve LAPS password from LDAP
        // https://github.com/swisskyrepo/SharpLAPS
        $guid_1E0986B4_4BF3_4CEA_A885_347B6D232D46 = "1E0986B4-4BF3-4CEA-A885-347B6D232D46" nocase

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_1e1f0cff_ff7a_406d_bd82_e53809a5e93a = "1e1f0cff-ff7a-406d-bd82-e53809a5e93a" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_1E2A1E78_ED0B_414B_A956_86232B1025BE = "1E2A1E78-ED0B-414B-A956-86232B1025BE" nocase

        // A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // https://github.com/PhrozenIO/SharpFtpC2
        $guid_1E474090_96A7_433C_BFE6_0F8B45DECC42 = "1E474090-96A7-433C-BFE6-0F8B45DECC42" nocase

        // Run Powershell without software restrictions.
        // https://github.com/iomoath/PowerShx
        $guid_1E70D62D_CC36_480F_82BB_E9593A759AF9 = "1E70D62D-CC36-480F-82BB-E9593A759AF9" nocase

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_1eb987e0_23a5_415e_9194_cd961314441b = "1eb987e0-23a5-415e-9194-cd961314441b" nocase

        // Keylogging server and client that uses DNS tunneling/exfiltration to transmit keystrokes
        // https://github.com/Geeoon/DNS-Tunnel-Keylogger
        $guid_1fc325f3_c548_43db_a13f_8c460dda8381 = "1fc325f3-c548-43db-a13f-8c460dda8381" nocase

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_1FDCAD33_E5D1_4D5F_ACD5_FA6F8661DFE5 = "1FDCAD33-E5D1-4D5F-ACD5-FA6F8661DFE5" nocase

        // A C# implementation of RDPThief to steal credentials from RDP
        // https://github.com/passthehashbrowns/SharpRDPThief
        $guid_20B3AA84_9CA7_43E5_B0CD_8DBA5091DF92 = "20B3AA84-9CA7-43E5-B0CD-8DBA5091DF92" nocase

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_210A3DB2_11E3_4BB4_BE7D_554935DCCA43 = "210A3DB2-11E3-4BB4-BE7D-554935DCCA43" nocase

        // Recovering NTLM hashes from Credential Guard
        // https://github.com/ly4k/PassTheChallenge
        $guid_2116E6C5_F609_4CA8_B1A1_E87B7BE770A4 = "2116E6C5-F609-4CA8-B1A1-E87B7BE770A4" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_211A4598_B46E_4CD3_BA5A_1EC259D4DB5A = "211A4598-B46E-4CD3-BA5A-1EC259D4DB5A" nocase

        // Adaptive DLL hijacking / dynamic export forwarding
        // https://github.com/monoxgas/Koppeling
        $guid_2150D252_AA17_45C2_8981_A6DCF7055CA6 = "2150D252-AA17-45C2-8981-A6DCF7055CA6" nocase

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_2164E6D9_6023_4932_A08F_7A5C15E2CA0B = "2164E6D9-6023-4932-A08F-7A5C15E2CA0B" nocase

        // Creating a persistent service
        // https://github.com/uknowsec/CreateService
        $guid_22020898_6F0D_4D71_B14D_CB5897C5A6AA = "22020898-6F0D-4D71-B14D-CB5897C5A6AA" nocase

        // Windows Privilege escalation POC exploitation for CVE-2024-49138
        // https://github.com/emdnaia/CVE-2024-49138-POC
        $guid_227c72ed_494a_4d29_9170_5e5994c12f5c = "227c72ed-494a-4d29-9170-5e5994c12f5c" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_2297A528_E866_4056_814A_D01C1C305A38 = "2297A528-E866-4056-814A-D01C1C305A38" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_22A156EA_2623_45C7_8E50_E864D9FC44D3 = "22A156EA-2623-45C7-8E50-E864D9FC44D3" nocase

        // C# implementation of harmj0y's PowerView
        // https://github.com/tevora-threat/SharpView/
        $guid_22A156EA_2623_45C7_8E50_E864D9FC44D3 = "22A156EA-2623-45C7-8E50-E864D9FC44D3" nocase

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_23975ac9_f51c_443a_8318_db006fd83100 = "23975ac9-f51c-443a-8318-db006fd83100" nocase

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_23A2E629_DC9D_46EA_8B5A_F1D60566EA09 = "23A2E629-DC9D-46EA-8B5A-F1D60566EA09" nocase

        // A tool that shows detailed information about named pipes in Windows
        // https://github.com/cyberark/PipeViewer
        $guid_2419CEDC_BF3A_4D8D_98F7_6403415BEEA4 = "2419CEDC-BF3A-4D8D-98F7-6403415BEEA4" nocase

        // Perform DCSync operation
        // https://github.com/notsoshant/DCSyncer
        $guid_253e716a_ab96_4f87_88c7_052231ec2a12 = "253e716a-ab96-4f87-88c7-052231ec2a12" nocase

        // Another Windows Local Privilege Escalation from Service Account to System
        // https://github.com/antonioCoco/JuicyPotatoNG
        $guid_261f880e_4bee_428d_9f64_c29292002c19 = "261f880e-4bee-428d-9f64-c29292002c19" nocase

        // XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // https://github.com/FSecureLABS/Xrulez
        $guid_2661F29C_69F5_4010_9198_A418C061DD7C = "2661F29C-69F5-4010-9198-A418C061DD7C" nocase

        // A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // https://github.com/mdsecactivebreach/DragonCastle
        $guid_274F19EC_7CBA_4FC7_80E6_BB41C1FE6728 = "274F19EC-7CBA-4FC7-80E6-BB41C1FE6728" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_27CF1AE0_5FDE_4B31_A4DA_6FAD1D77351D = "27CF1AE0-5FDE-4B31-A4DA-6FAD1D77351D" nocase

        // Local Privilege Escalation from Admin to Kernel vulnerability on Windows 10 and Windows 11 operating systems with HVCI enabled.
        // https://github.com/hakaioffsec/CVE-2024-21338
        $guid_27E42E24_9F76_44E2_B1D6_82F68D5C4466 = "27E42E24-9F76-44E2-B1D6-82F68D5C4466" nocase

        // Persistence by writing/reading shellcode from Event Log
        // https://github.com/improsec/SharpEventPersist
        $guid_27F85701_FD37_4D18_A107_20E914F8E779 = "27F85701-FD37-4D18-A107-20E914F8E779" nocase

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_28CF3837_FF58_463B_AF81_E6B0039DE55F = "28CF3837-FF58-463B-AF81-E6B0039DE55F" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_28F9E001_67E0_4200_B120_3021596689E9 = "28F9E001-67E0-4200-B120-3021596689E9" nocase

        // Github as C2
        // https://github.com/TheD1rkMtr/GithubC2
        $guid_29446C11_A1A5_47F6_B418_0D699C6C3339 = "29446C11-A1A5-47F6-B418-0D699C6C3339" nocase

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_2944dbfc_8a1e_4759_a8a2_e4568950601d = "2944dbfc-8a1e-4759-a8a2-e4568950601d" nocase

        // Remote Command Executor: A OSS replacement for PsExec and RunAs
        // https://github.com/kavika13/RemCom
        $guid_29548EB7_5E44_21F9_5C82_15DDDC80449A = "29548EB7-5E44-21F9-5C82-15DDDC80449A" nocase

        // SharpStay - .NET Persistence
        // https://github.com/0xthirteen/SharpStay
        $guid_2963C954_7B1E_47F5_B4FA_2FC1F0D56AEA = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" nocase

        // SharpStay - .NET Persistence
        // https://github.com/0xthirteen/SharpStay
        $guid_2963C954_7B1E_47F5_B4FA_2FC1F0D56AEA = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" nocase

        // Dump the memory of any PPL with a Userland exploit chain
        // https://github.com/itm4n/PPLmedic
        $guid_29CBBC24_363F_42D7_B018_5EF068BA8777 = "29CBBC24-363F-42D7-B018-5EF068BA8777" nocase

        // SharpSpray is a Windows domain password spraying tool written in .NET C#
        // https://github.com/iomoath/SharpSpray
        $guid_29CFAA16_9277_4EFB_9E91_A7D11225160B = "29CFAA16-9277-4EFB-9E91-A7D11225160B" nocase

        // RDP Wrapper Library used by malwares
        // https://github.com/stascorp/rdpwrap
        $guid_29E4E73B_EBA6_495B_A76C_FBB462196C64 = "29E4E73B-EBA6-495B-A76C-FBB462196C64" nocase

        // ArtsOfGetSystem privesc tools
        // https://github.com/daem0nc0re/PrivFu/
        $guid_2AD3951D_DEA6_4CF7_88BE_4C73344AC9DA = "2AD3951D-DEA6-4CF7-88BE-4C73344AC9DA" nocase

        // DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // https://github.com/lypd0/DeadPotato
        $guid_2AE886C3_3272_40BE_8D3C_EBAEDE9E61E1 = "2AE886C3-3272-40BE-8D3C-EBAEDE9E61E1" nocase

        // GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // https://github.com/BeichenDream/GodPotato
        $guid_2AE886C3_3272_40BE_8D3C_EBAEDE9E61E1 = "2AE886C3-3272-40BE-8D3C-EBAEDE9E61E1" nocase

        // SeImpersonate privilege escalation tool
        // https://github.com/tylerdotrar/SigmaPotato
        $guid_2AE886C3_3272_40BE_8D3C_EBAEDE9E61E1 = "2AE886C3-3272-40BE-8D3C-EBAEDE9E61E1" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_2B47F84C_9CA3_47E9_9970_8AF8233A9F12 = "2B47F84C-9CA3-47E9-9970-8AF8233A9F12" nocase

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_2B704D89_41B9_4051_A51C_36A82ACEBE10 = "2B704D89-41B9-4051-A51C-36A82ACEBE10" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_2B914EE7_F206_4A83_B435_460D054315BB = "2B914EE7-F206-4A83-B435-460D054315BB" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_2C059FE7_C868_4C6D_AFA0_D62BA3C1B2E1 = "2C059FE7-C868-4C6D-AFA0-D62BA3C1B2E1" nocase

        // MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // https://github.com/Xre0uS/MultiDump
        $guid_2C6D323A_B51F_47CB_AD37_972FD051D475 = "2C6D323A-B51F-47CB-AD37-972FD051D475" nocase

        // injection technique abusing windows fork API to evade EDRs
        // https://github.com/deepinstinct/Dirty-Vanity
        $guid_2C809982_78A1_4F1C_B0E8_C957C93B242F = "2C809982-78A1-4F1C-B0E8-C957C93B242F" nocase

        // Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // https://github.com/deepinstinct/NoFilter
        $guid_2CFB9E9E_479D_4E23_9A8E_18C92E06B731 = "2CFB9E9E-479D-4E23-9A8E-18C92E06B731" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_2D6FDD44_39B1_4FF8_8AE0_60A6B0979F5F = "2D6FDD44-39B1-4FF8-8AE0-60A6B0979F5F" nocase

        // This PoC shows a technique that can be used to weaponize privileged file write vulnerabilities on Windows. It provides an alternative to the DiagHub DLL loading exploit 
        // https://github.com/itm4n/UsoDllLoader
        $guid_2D863D7A_A369_419C_B4B3_54BDB88B5816 = "2D863D7A-A369-419C-B4B3-54BDB88B5816" nocase

        // Hotkey-based keylogger for Windows
        // https://github.com/yo-yo-yo-jbo/hotkeyz
        $guid_2deff2ca_c313_4d85_aeee_414bac32e7ae = "2deff2ca-c313-4d85-aeee-414bac32e7ae" nocase

        // Windows injection of x86/x64 DLL and Shellcode
        // https://github.com/Joe1sn/S-inject
        $guid_2E98B8D4_7A26_4F04_A95D_2051B0AB884C = "2E98B8D4-7A26-4F04-A95D-2051B0AB884C" nocase

        // p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET). It has a lot of offensive PowerShell modules and binaries included to make the process of Post Exploitation easier. What we tried was to build an ?all in one? Post Exploitation tool which we could use to bypass all mitigations solutions (or at least some off). and that has all relevant tooling included. You can use it to perform modern attacks within Active Directory environments and create awareness within your Blue team so they can build the right defense strategies.
        // https://github.com/Cn33liz/p0wnedShell
        $guid_2E9B1462_F47C_48CA_9D85_004493892381 = "2E9B1462-F47C-48CA-9D85-004493892381" nocase

        // SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // https://github.com/GhostPack/SharpDPAPI
        $guid_2F00A05B_263D_4FCC_846B_DA82BD684603 = "2F00A05B-263D-4FCC-846B-DA82BD684603" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_2F00A05B_263D_4FCC_846B_DA82BD684603 = "2F00A05B-263D-4FCC-846B-DA82BD684603" nocase

        // Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // https://github.com/Imanfeng/Telemetry
        $guid_2f00a05b_263d_4fcc_846b_da82bd684603 = "2f00a05b-263d-4fcc-846b-da82bd684603" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_2FB94059_2D49_4EEA_AAF8_7E89E249644B = "2FB94059-2D49-4EEA-AAF8-7E89E249644B" nocase

        // Crack any Microsoft Windows users password without any privilege (Guest account included)
        // https://github.com/PhrozenIO/win-brute-logon
        $guid_2FE6C1D0_0538_48DB_B4FA_55F0296A5150 = "2FE6C1D0-0538-48DB-B4FA-55F0296A5150" nocase

        // PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // https://github.com/poweradminllc/PAExec
        $guid_2FEB96F5_08E6_48A3_B306_794277650A08 = "2FEB96F5-08E6-48A3-B306-794277650A08" nocase

        // PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // https://github.com/poweradminllc/PAExec
        $guid_2FEB96F5_08E6_48A3_B306_794277650A08 = "2FEB96F5-08E6-48A3-B306-794277650A08" nocase

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_304D5A8A_EF98_4E21_8F4D_91E66E0BECAC = "304D5A8A-EF98-4E21-8F4D-91E66E0BECAC" nocase

        // Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // https://github.com/outflanknl/Dumpert
        $guid_307088B9_2992_4DE7_A57D_9E657B1CE546 = "307088B9-2992-4DE7-A57D-9E657B1CE546" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_30B8883F_A0A2_4256_ADCF_A790525D3696 = "30B8883F-A0A2-4256-ADCF-A790525D3696" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_310FC5BE_6F5E_479C_A246_6093A39296C0 = "310FC5BE-6F5E-479C-A246-6093A39296C0" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_32223BE8_3E78_489C_92ED_7900B26DFF43 = "32223BE8-3E78-489C-92ED-7900B26DFF43" nocase

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_326D0AB1_CF2F_4A9B_B612_04B62D4EBA89 = "326D0AB1-CF2F-4A9B-B612-04B62D4EBA89" nocase

        // enabling Recall in Windows 11 version 24H2 on unsupported devices
        // https://github.com/thebookisclosed/AmperageKit
        $guid_327F3F26_182F_4E58_ABEA_A0CEDBCA0FCD = "327F3F26-182F-4E58-ABEA-A0CEDBCA0FCD" nocase

        // Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // https://github.com/quasar/Quasar
        $guid_32A2A734_7429_47E6_A362_E344A19C0D85 = "32A2A734-7429-47E6-A362-E344A19C0D85" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_32CE1CB1_B7D9_416F_8EFE_6A0055867537 = "32CE1CB1-B7D9-416F-8EFE-6A0055867537" nocase

        // enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // https://github.com/FalconForceTeam/SOAPHound
        $guid_33571B09_4E94_43CB_ABDC_0226D769E701 = "33571B09-4E94-43CB-ABDC-0226D769E701" nocase

        // CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // https://github.com/Prepouce/CoercedPotato
        $guid_337ED7BE_969A_40C4_A356_BE99561F4633 = "337ED7BE-969A-40C4-A356-BE99561F4633" nocase

        // Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // https://github.com/sokaRepo/CoercedPotatoRDLL
        $guid_337ED7BE_969A_40C4_A356_BE99561F4633 = "337ED7BE-969A-40C4-A356-BE99561F4633" nocase

        // RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // https://github.com/tastypepperoni/RunAsWinTcb
        $guid_33BF8AA2_18DE_4ED9_9613_A4118CBFC32A = "33BF8AA2-18DE-4ED9-9613-A4118CBFC32A" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3504F678_95FA_4DB2_8437_31A927CABC16 = "3504F678-95FA-4DB2-8437-31A927CABC16" nocase

        // SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $guid_360F9CE5_D927_46B9_8416_4118D0B68360 = "360F9CE5-D927-46B9-8416-4118D0B68360" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_363A6DE4_59D9_451B_A4FD_1FE763970E1E = "363A6DE4-59D9-451B-A4FD-1FE763970E1E" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_36AB45D2_F886_4803_AA7E_6FD5520458FC = "36AB45D2-F886-4803-AA7E-6FD5520458FC" nocase

        // Keylogger written in C#
        // https://github.com/djhohnstein/SharpLogger
        $guid_36E00152_E073_4DA8_AA0C_375B6DD680C4 = "36E00152-E073-4DA8-AA0C-375B6DD680C4" nocase

        // Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // https://github.com/p3nt4/PowerShdll
        $guid_36EBF9AA_2F37_4F1D_A2F1_F2A45DEEAF21 = "36EBF9AA-2F37-4F1D-A2F1-F2A45DEEAF21" nocase

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_36F9C306_5F45_4946_A259_610C05BD90DF = "36F9C306-5F45-4946-A259-610C05BD90DF" nocase

        // DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // https://github.com/MzHmO/DebugAmsi
        $guid_375D8508_F60D_4E24_9DF6_1E591D2FA474 = "375D8508-F60D-4E24-9DF6-1E591D2FA474" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_3787435B_8352_4BD8_A1C6_E5A1B73921F4 = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" nocase

        // Console Application designed to interact with SharpSploit
        // https://github.com/anthemtotheego/SharpSploitConsole
        $guid_3787435B_8352_4BD8_A1C6_E5A1B73921F4 = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_378FC1AA_37BD_4C61_B5DE_4E45C2CDB8C9 = "378FC1AA-37BD-4C61-B5DE-4E45C2CDB8C9" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_37E20BAF_3577_4CD9_BB39_18675854E255 = "37E20BAF-3577-4CD9-BB39-18675854E255" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_382B6332_4A57_458D_96EB_B312688A7604 = "382B6332-4A57-458D-96EB-B312688A7604" nocase

        // Command and control server - multi-person collaborative penetration testing graphical framework
        // https://github.com/INotGreen/Xiebro-Plugins
        $guid_38AF011B_95F8_4F42_B4B9_B1AEE328A583 = "38AF011B-95F8-4F42-B4B9-B1AEE328A583" nocase

        // AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // https://github.com/AutoHotkey/AutoHotkey
        $guid_39037993_9571_4DF2_8E39_CD2909043574 = "39037993-9571-4DF2-8E39-CD2909043574" nocase

        // EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // https://github.com/wavestone-cdt/EDRSandblast
        $guid_3A2FCB56_01A3_41B3_BDAA_B25F45784B23 = "3A2FCB56-01A3-41B3-BDAA-B25F45784B23" nocase

        // Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // https://github.com/gabriellandau/EDRSandblast-GodFault
        $guid_3A2FCB56_01A3_41B3_BDAA_B25F45784B23 = "3A2FCB56-01A3-41B3-BDAA-B25F45784B23" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3ADB8BB1_AE14_49DA_A7E1_1C0D9BEB76E9 = "3ADB8BB1-AE14-49DA-A7E1-1C0D9BEB76E9" nocase

        // acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // https://github.com/decoder-it/KrbRelay-SMBServer
        $guid_3B47EEBC_0D33_4E0B_BAB5_782D2D3680AF = "3B47EEBC-0D33-4E0B-BAB5-782D2D3680AF" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3B85D7A9_6BD0_4CD8_9009_36554EF24D32 = "3B85D7A9-6BD0-4CD8-9009-36554EF24D32" nocase

        // DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // https://github.com/outflanknl/NetshHelperBeacon
        $guid_3BB0CD58_487C_4FEC_8001_607599477158 = "3BB0CD58-487C-4FEC-8001-607599477158" nocase

        // Modular C# framework to exfiltrate loot over secure and trusted channels.
        // https://github.com/Flangvik/SharpExfiltrate
        $guid_3bb553cd_0a48_402d_9812_8daff60ac628 = "3bb553cd-0a48-402d-9812-8daff60ac628" nocase

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_3BEF8A16_981F_4C65_8AE7_C612B46BE446 = "3BEF8A16-981F-4C65-8AE7-C612B46BE446" nocase

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_3C21F82B_B958_457A_82BB_B8A795316D3D = "3C21F82B-B958-457A-82BB-B8A795316D3D" nocase

        // A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // https://github.com/TheD1rkMtr/TakeMyRDP
        $guid_3C601672_7389_42B2_B5C9_059846E1DA88 = "3C601672-7389-42B2-B5C9-059846E1DA88" nocase

        // Enable or Disable TokenPrivilege(s)
        // https://github.com/xvt-void/EnableAllTokenPrivs
        $guid_3C8AA457_3659_4CDD_A685_66F7ED10DC4F = "3C8AA457-3659-4CDD-A685-66F7ED10DC4F" nocase

        // disable windows defender. (through the WSC api)
        // https://github.com/es3n1n/no-defender
        $guid_3CFB521D_40ED_4891_8B6C_ED0644A237C1 = "3CFB521D-40ED-4891-8B6C-ED0644A237C1" nocase

        // OPSEC safe Kerberoasting in C#
        // https://github.com/Luct0r/KerberOPSEC
        $guid_3D111394_E7F7_40B7_91CB_D24374DB739A = "3D111394-E7F7-40B7-91CB-D24374DB739A" nocase

        // .NET assembly to interact with services. (included in powershell empire)
        // https://github.com/djhohnstein/SharpSC
        $guid_3D9D679D_6052_4C5E_BD91_2BC3DED09D0A = "3D9D679D-6052-4C5E-BD91-2BC3DED09D0A" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3EAB01B5_9B49_48D8_BFA1_5493B26CCB71 = "3EAB01B5-9B49-48D8-BFA1-5493B26CCB71" nocase

        // Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // https://github.com/rasta-mouse/ThreatCheck
        $guid_3EC9B9A8_0AFE_44A7_8B95_7F60E750F042 = "3EC9B9A8-0AFE-44A7-8B95-7F60E750F042" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_3F0C3D9A_CFB8_4DB5_8419_1C28CBC8621D = "3F0C3D9A-CFB8-4DB5-8419-1C28CBC8621D" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3F5558BD_7B94_4CB0_A46C_A7252B5BCA17 = "3F5558BD-7B94-4CB0-A46C-A7252B5BCA17" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_3FBBC3DD_39D9_4D8C_AF73_EDC3D2849DEB = "3FBBC3DD-39D9-4D8C-AF73-EDC3D2849DEB" nocase

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_3FCA8012_3BAD_41E4_91F4_534AA9A44F96 = "3FCA8012-3BAD-41E4-91F4-534AA9A44F96" nocase

        // Remote Shellcode Injector
        // https://github.com/florylsk/NtRemoteLoad
        $guid_40B05F26_6A2F_40BC_88DE_F40D4BC77FB0 = "40B05F26-6A2F-40BC-88DE-F40D4BC77FB0" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_40C64006_EE9C_4EC8_A378_B8499142C071 = "40C64006-EE9C-4EC8-A378-B8499142C071" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_40C6A1BB_69AA_4869_81EE_41917D0B009A = "40C6A1BB-69AA-4869-81EE-41917D0B009A" nocase

        // Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // https://github.com/unkvolism/Fuck-Etw
        $guid_40E7714F_460D_4CA6_9A5A_FB32C6769BE4 = "40E7714F-460D-4CA6-9A5A-FB32C6769BE4" nocase

        // Tool to execute token assigned process
        // https://github.com/daem0nc0re/PrivFu
        $guid_410D25CC_A75E_4B65_8D24_05FA4D8AE0B9 = "410D25CC-A75E-4B65-8D24-05FA4D8AE0B9" nocase

        // coercing machine authentication but specific for ADCS server
        // https://github.com/decoder-it/ADCSCoercePotato
        $guid_4164003E_BA47_4A95_8586_D5AAC399C050 = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase

        // Windows Local Privilege Escalation from Service Account to System
        // https://github.com/uknowsec/JuicyPotato
        $guid_4164003E_BA47_4A95_8586_D5AAC399C050 = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase

        // perform the RottenPotato attack and get a handle to a privileged token
        // https://github.com/breenmachine/RottenPotatoNG
        $guid_4164003E_BA47_4A95_8586_D5AAC399C050 = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_416656DC_D499_498B_8ACF_6502A13EFC9E = "416656DC-D499-498B-8ACF-6502A13EFC9E" nocase

        // disable windows defender. (through the WSC api)
        // https://github.com/es3n1n/no-defender
        $guid_4193DE42_C103_45FF_A04D_0AD64616BC59 = "4193DE42-C103-45FF-A04D-0AD64616BC59" nocase

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD753 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD753" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD753 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD753" nocase

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD754 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD754" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD754 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD754" nocase

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD755 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD755" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD755 = "41A90A6A-F9ED-4A2F-8448-D544EC1FD755" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_424B81BE_2FAC_419F_B4BC_00CCBE38491F = "424B81BE-2FAC-419F-B4BC-00CCBE38491F" nocase

        // SharpElevator is a C# implementation of Elevator for UAC bypass
        // https://github.com/eladshamir/SharpElevator
        $guid_42BDEFC0_0BAE_43DF_97BB_C805ABFBD078 = "42BDEFC0-0BAE-43DF-97BB-C805ABFBD078" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_4349B8A8_F17B_44D5_AE4D_21BE9C9D1573 = "4349B8A8-F17B-44D5-AE4D-21BE9C9D1573" nocase

        // An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // https://github.com/eladshamir/BadWindowsService
        $guid_43A031B0_E040_4D5E_B477_02651F5E3D62 = "43A031B0-E040-4D5E-B477-02651F5E3D62" nocase

        // interactive remote shell access via named pipes and the SMB protocol.
        // https://github.com/DarkCoderSc/SharpShellPipe
        $guid_43BB3C30_39D7_4B6B_972E_1E2B94D4D53A = "43BB3C30-39D7-4B6B-972E-1E2B94D4D53A" nocase

        // Tool to create hidden registry keys
        // https://github.com/outflanknl/SharpHide
        $guid_443D8CBF_899C_4C22_B4F6_B7AC202D4E37 = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" nocase

        // Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // https://github.com/daem0nc0re/PrivFu
        $guid_449CE476_7B27_47F5_B09C_570788A2F261 = "449CE476-7B27-47F5-B09C-570788A2F261" nocase

        // A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // https://github.com/PhrozenIO/SharpFtpC2
        $guid_44D0366D_742F_4E0B_A67D_3B1044A66EA7 = "44D0366D-742F-4E0B-A67D-3B1044A66EA7" nocase

        // Shoggoth: Asmjit Based Polymorphic Encryptor
        // https://github.com/frkngksl/Shoggoth
        $guid_44D5BE95_F34D_4CC5_846F_C7758943B8FA = "44D5BE95-F34D-4CC5-846F-C7758943B8FA" nocase

        // A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // https://github.com/SafeBreach-Labs/PoolParty
        $guid_45D59D79_EF51_4A93_AAFA_2879FFC3A62C = "45D59D79-EF51-4A93-AAFA-2879FFC3A62C" nocase

        // Tunnel TCP connections through a file
        // https://github.com/fiddyschmitt/File-Tunnel
        $guid_461F72D2_6BDC_4D0E_82EE_59A811AB4844 = "461F72D2-6BDC-4D0E-82EE-59A811AB4844" nocase

        // GPO attack vectors through NTLM relaying
        // https://github.com/synacktiv/GPOddity
        $guid_46993522_7D77_4B59_9B77_F82082DE9D81 = "46993522-7D77-4B59-9B77-F82082DE9D81" nocase

        // dump LSASS memory
        // https://github.com/Offensive-Panda/ShadowDumper
        $guid_46D3E566_0EBA_4BD9_925E_84F4CB9EE7BC = "46D3E566-0EBA-4BD9-925E-84F4CB9EE7BC" nocase

        // An App Domain Manager Injection DLL PoC
        // https://github.com/ipSlav/DirtyCLR
        $guid_46EB7B83_3404_4DFC_94CC_704B02D11464 = "46EB7B83-3404-4DFC-94CC-704B02D11464" nocase

        // A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $guid_474B99B7_66C4_4AC2_8AD3_065DD13DDDFF = "474B99B7-66C4-4AC2-8AD3-065DD13DDDFF" nocase

        // A quick scanner for the CVE-2019-0708 "BlueKeep" vulnerability
        // https://github.com/robertdavidgraham/rdpscan
        $guid_475F1C8A_F70D_45C0_95E5_EB783935277D = "475F1C8A-F70D-45C0-95E5-EB783935277D" nocase

        // Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // https://github.com/ricardojoserf/NativeDump
        $guid_476FC126_239F_4D58_8389_E1C0E93C2C5E = "476FC126-239F-4D58-8389-E1C0E93C2C5E" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_487E2246_72F1_4BD3_AA8A_A9B8C79C9F28 = "487E2246-72F1-4BD3-AA8A-A9B8C79C9F28" nocase

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_497CA37F_506C_46CD_9B8D_F9BB0DA34B95 = "497CA37F-506C-46CD-9B8D-F9BB0DA34B95" nocase

        // Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // https://github.com/BC-SECURITY/Moriarty
        $guid_49AD5F38_9E37_4967_9E84_FE19C7434ED7 = "49AD5F38-9E37-4967-9E84-FE19C7434ED7" nocase

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_4B2E3A60_9A8F_4F36_8692_14ED9887E7BE = "4B2E3A60-9A8F-4F36-8692-14ED9887E7BE" nocase

        // Command and control server - multi-person collaborative penetration testing graphical framework
        // https://github.com/INotGreen/Xiebro-Plugins
        $guid_4B37C8BF_B1C1_4025_93C6_C3B501CBB152 = "4B37C8BF-B1C1-4025-93C6-C3B501CBB152" nocase

        // A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // https://www.duckdns.org/install.jsp
        $guid_4B9C98F6_AF30_4280_873D_B45C7A7B89EB = "4B9C98F6-AF30-4280-873D-B45C7A7B89EB" nocase

        // Documents Exfiltration and C2 project
        // https://github.com/TheD1rkMtr/DocPlz
        $guid_4C3B106C_8782_4374_9459_851749072123 = "4C3B106C-8782-4374-9459-851749072123" nocase

        // manage user right without secpol.msc
        // https://github.com/daem0nc0re/PrivFu
        $guid_4C496D14_FA2B_428C_BB15_20B25BAB9B73 = "4C496D14-FA2B-428C-BB15-20B25BAB9B73" nocase

        // Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // https://github.com/daem0nc0re/PrivFu
        $guid_4C574B86_DC07_47EA_BB02_FD50AE002910 = "4C574B86-DC07-47EA-BB02-FD50AE002910" nocase

        // Kernel Mode WinDbg extension for token privilege edit
        // https://github.com/daem0nc0re/PrivFu
        $guid_4C61F4EA_D946_4AF2_924B_7A873B4D964B = "4C61F4EA-D946-4AF2-924B-7A873B4D964B" nocase

        // Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // https://github.com/ly4k/SpoolFool
        $guid_4c7714ee_c58d_4ef7_98f2_b162baec0ee0 = "4c7714ee-c58d-4ef7-98f2-b162baec0ee0" nocase

        // reads all computer information related to successful (4624) or failed (4625) logins on the local machine to quickly identify operations and maintenance personnel during internal network penetration
        // https://github.com/uknowsec/SharpEventLog
        $guid_4CA05D5C_AF6B_4F45_81E0_788BAA8D11A2 = "4CA05D5C-AF6B-4F45-81E0-788BAA8D11A2" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_4D164EDE_7180_4A1B_BE82_59BB87542037 = "4D164EDE-7180-4A1B-BE82-59BB87542037" nocase

        // Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // https://github.com/reveng007/DarkWidow
        $guid_4D1B765D_1287_45B1_AEDC_C4B96CF5CAA2 = "4D1B765D-1287-45B1-AEDC-C4B96CF5CAA2" nocase

        // UAC bypass for x64 Windows 7 - 11
        // https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $guid_4d3bae5b_eb71_413b_adb2_a58f1fa2ad64 = "4d3bae5b-eb71-413b-adb2-a58f1fa2ad64" nocase

        // Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // https://github.com/GhostPack/Koh
        $guid_4d5350c8_7f8c_47cf_8cde_c752018af17e = "4d5350c8-7f8c-47cf-8cde-c752018af17e" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_4D71336E_6EF6_4DF1_8457_B94DC3D73FE7 = "4D71336E-6EF6-4DF1-8457-B94DC3D73FE7" nocase

        // SingleDose is a framework to build shellcode load/process injection techniques
        // https://github.com/Wra7h/SingleDose
        $guid_4D7AEF0B_5AA6_4AE5_971E_7141AA1FDAFC = "4D7AEF0B-5AA6-4AE5-971E-7141AA1FDAFC" nocase

        // GhostMapper involves modifying Windows system "dump_" prefix drivers to exploit crash handling mechanisms for malicious purposes.
        // https://github.com/Oliver-1-1/GhostMapper
        $guid_4D7BA537_54EC_4005_9CC2_AE134B4526F9 = "4D7BA537-54EC-4005-9CC2-AE134B4526F9" nocase

        // Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // https://github.com/S1lkys/SharpKiller
        $guid_4DD3206C_F14A_43A3_8EA8_88676810B8CD = "4DD3206C-F14A-43A3-8EA8-88676810B8CD" nocase

        // unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $guid_4DE43724_3851_4376_BB6C_EA15CF500C44 = "4DE43724-3851-4376-BB6C-EA15CF500C44" nocase

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_4ED3C17D_33E6_4B86_9FA0_DA774B7CD387 = "4ED3C17D-33E6-4B86-9FA0-DA774B7CD387" nocase

        // Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // https://github.com/Mayyhem/Maestro
        $guid_4EE2C7E8_095D_490A_9465_9B4BB9070669 = "4EE2C7E8-095D-490A-9465-9B4BB9070669" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_4EF73752_78B0_4E0D_A33B_B6637B6C2177 = "4EF73752-78B0-4E0D-A33B-B6637B6C2177" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_4F169EA5_8854_4258_9D2C_D44F37D88776 = "4F169EA5-8854-4258-9D2C-D44F37D88776" nocase

        // Abuses the Windows containers framework to bypass EDRs.
        // https://github.com/deepinstinct/ContainYourself
        $guid_4F2AD0E0_8C4D_45CB_97DE_CE8D4177E7BF = "4F2AD0E0-8C4D-45CB-97DE-CE8D4177E7BF" nocase

        // Manage everything in one place
        // https://github.com/fleetdm/fleet
        $guid_4F748D41_5BE1_4626_A0AB_9EA15CDC2074 = "4F748D41-5BE1-4626-A0AB-9EA15CDC2074" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_4FB03AD0_96FF_4730_801A_4F997795D920 = "4FB03AD0-96FF-4730-801A-4F997795D920" nocase

        // SAM dumping via the registry in C#/.NET
        // https://github.com/jojonas/SharpSAMDump
        $guid_4FEAB888_F514_4F2E_A4F7_5989A86A69DE = "4FEAB888-F514-4F2E-A4F7-5989A86A69DE" nocase

        // Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // https://github.com/p3nt4/PowerShdll
        $guid_5067F916_9971_47D6_BBCB_85FB3982584F = "5067F916-9971-47D6-BBCB-85FB3982584F" nocase

        // Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // https://github.com/Metro-Holografix/DInjector
        $guid_5086CE01_1032_4CA3_A302_6CFF2A8B64DC = "5086CE01-1032-4CA3-A302-6CFF2A8B64DC" nocase

        // DCOM Lateral Movement
        // https://github.com/rvrsh3ll/SharpCOM
        $guid_51960F7D_76FE_499F_AFBD_ACABD7BA50D1 = "51960F7D-76FE-499F-AFBD-ACABD7BA50D1" nocase

        // Asynchronous Password Spraying Tool in C# for Windows Environments
        // https://github.com/ustayready/SharpHose
        $guid_51C6E016_1428_441D_82E9_BB0EB599BBC8 = "51C6E016-1428-441D-82E9-BB0EB599BBC8" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_51E46096_4A36_4C7D_9773_BC28DBDC4FC6 = "51E46096-4A36-4C7D-9773-BC28DBDC4FC6" nocase

        // SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // https://github.com/cobbr/SharpSploit
        $guid_52040049_D7FC_4C72_B6AE_BD2C7AB27DEE = "52040049-D7FC-4C72-B6AE-BD2C7AB27DEE" nocase

        // BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // https://github.com/AlessandroZ/BeRoot
        $guid_52B0FF57_7E0A_4CA9_84D4_58DFA2456BA5 = "52B0FF57-7E0A-4CA9-84D4-58DFA2456BA5" nocase

        // active directory weakness scan Vulnerability scanner
        // https://github.com/netwrix/pingcastle
        $guid_52BBA3C2_A74E_4096_B65F_B88C38F92120 = "52BBA3C2-A74E-4096-B65F-B88C38F92120" nocase

        // search the current domain for computers and get bindings for all of them
        // https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $guid_52BBA3C2_A74E_4096_B65F_B88C38F92120 = "52BBA3C2-A74E-4096-B65F-B88C38F92120" nocase

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_53182258_F40E_4104_AFC6_1F327E556E77 = "53182258-F40E-4104-AFC6-1F327E556E77" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_534D9A24_3138_4209_A4C6_6B9C1EF0B579 = "534D9A24-3138-4209-A4C6-6B9C1EF0B579" nocase

        // injection technique abusing windows fork API to evade EDRs
        // https://github.com/deepinstinct/Dirty-Vanity
        $guid_53891DF6_3F6D_DE4B_A8CD_D89E94D0C8CD = "53891DF6-3F6D-DE4B-A8CD-D89E94D0C8CD" nocase

        // This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // https://github.com/nettitude/MalSCCM
        $guid_5439CECD_3BB3_4807_B33F_E4C299B71CA2 = "5439CECD-3BB3-4807-B33F-E4C299B71CA2" nocase

        // similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // https://github.com/CICADA8-Research/RemoteKrbRelay
        $guid_5494EDD3_132D_4238_AC25_FA384D78D4E3 = "5494EDD3-132D-4238-AC25-FA384D78D4E3" nocase

        // NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // https://github.com/bitsadmin/nopowershell
        $guid_555AD0AC_1FDB_4016_8257_170A74CB2F55 = "555AD0AC-1FDB-4016-8257-170A74CB2F55" nocase

        // NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // https://github.com/bitsadmin/nopowershell
        $guid_555AD0AC_1FDB_4016_8257_170A74CB2F55 = "555AD0AC-1FDB-4016-8257-170A74CB2F55" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_55625889_F7BB_4533_9702_DDE98FBB0DDF = "55625889-F7BB-4533-9702-DDE98FBB0DDF" nocase

        // A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // https://github.com/OmriBaso/BesoToken
        $guid_55A48A19_1A5C_4E0D_A46A_5DB04C1D8B03 = "55A48A19-1A5C-4E0D-A46A-5DB04C1D8B03" nocase

        // Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // https://github.com/TheD1rkMtr/BlockOpenHandle
        $guid_55F0368B_63DA_40E7_A8A5_289F70DF9C7F = "55F0368B-63DA-40E7-A8A5-289F70DF9C7F" nocase

        // Payload Generation Framework
        // https://github.com/mdsecactivebreach/SharpShooter
        $guid_56598F1C_6D88_4994_A392_AF337ABE5777 = "56598F1C-6D88-4994-A392-AF337ABE5777" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_56F981FD_634A_4656_85A7_5636658E1F94 = "56F981FD-634A-4656-85A7-5636658E1F94" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_5745976E_48A7_4F79_9BAA_82D1F43D1261 = "5745976E-48A7-4F79-9BAA-82D1F43D1261" nocase

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_5782C660_DD26_40DC_B06C_B9275371EC55 = "5782C660-DD26-40DC-B06C-B9275371EC55" nocase

        // Utility to craft HTML or SVG smuggled files for Red Team engagements
        // https://github.com/surajpkhetani/AutoSmuggle
        $guid_57A893C7_7527_4B55_B4E9_D644BBDA89D1 = "57A893C7-7527-4B55-B4E9-D644BBDA89D1" nocase

        // This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // https://github.com/redskal/SharpAzbelt
        $guid_57D4D4F4_F083_47A3_AE33_AE2500ABA3B6 = "57D4D4F4-F083-47A3-AE33-AE2500ABA3B6" nocase

        // DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // https://github.com/deepinstinct/DCOMUploadExec
        $guid_57FD94EC_4361_43FD_AB9D_CDB254C0DE8F = "57FD94EC-4361-43FD-AB9D-CDB254C0DE8F" nocase

        // Creating a persistent service
        // https://github.com/uknowsec/CreateService
        $guid_580ba177_cf9a_458c_a692_36dd6f23ea77 = "580ba177-cf9a-458c-a692-36dd6f23ea77" nocase

        // LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // https://github.com/CCob/MirrorDump
        $guid_58338E42_6010_493C_B8C8_2FD2CFC30FFB = "58338E42-6010-493C-B8C8-2FD2CFC30FFB" nocase

        // A fake AMSI Provider which can be used for persistence
        // https://github.com/netbiosX/AMSI-Provider
        $guid_58B32FCA_F385_4500_9A8E_7CBA1FC9BA13 = "58B32FCA-F385-4500-9A8E-7CBA1FC9BA13" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_59224C16_39C5_49EA_8525_F493DC1D66FE = "59224C16-39C5-49EA-8525-F493DC1D66FE" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_595D5812_AA30_4EDE_95DA_8EDD7B8844BD = "595D5812-AA30-4EDE-95DA-8EDD7B8844BD" nocase

        // MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // https://github.com/senzee1984/MutationGate
        $guid_5A0FBE0D_BACC_4B97_8578_B5B27567EEA7 = "5A0FBE0D-BACC-4B97-8578-B5B27567EEA7" nocase

        // a very fast brute force webshell password tool
        // https://github.com/shmilylty/cheetah
        $guid_5a1f9b0e_9f7c_4673_bf16_4740707f41b7 = "5a1f9b0e-9f7c-4673-bf16-4740707f41b7" nocase

        // Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // https://github.com/TheD1rkMtr/Pspersist
        $guid_5A403F3C_9136_4B67_A94E_02D3BCD3162D = "5A403F3C-9136-4B67-A94E-02D3BCD3162D" nocase

        // Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // https://github.com/TheD1rkMtr/StackCrypt
        $guid_5A6F942E_888A_4CE1_A6FB_1AB8AE22AFFA = "5A6F942E-888A-4CE1-A6FB-1AB8AE22AFFA" nocase

        // Windows rootkit designed to work with BYOVD exploits
        // https://github.com/ColeHouston/Sunder
        $guid_5a958c89_6327_401c_a214_c89e54855b57 = "5a958c89-6327-401c-a214-c89e54855b57" nocase

        // Executes PowerShell from an unmanaged process
        // https://github.com/leechristensen/UnmanagedPowerShell
        $guid_5A9955E4_62B7_419D_AB73_01A6D7DD27FC = "5A9955E4-62B7-419D-AB73-01A6D7DD27FC" nocase

        // using RasMan service for privilege escalation
        // https://github.com/crisprss/RasmanPotato
        $guid_5AC309CE_1223_4FF5_AF84_24BCD0B9E4DC = "5AC309CE-1223-4FF5-AF84-24BCD0B9E4DC" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_5b2ec674_0aa4_4209_94df_b6c995ad59c4 = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase

        // Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // https://github.com/Meltedd/HVNC
        $guid_5C3AD9AC_C62C_4AA8_BAE2_9AF920A652E3 = "5C3AD9AC-C62C-4AA8-BAE2-9AF920A652E3" nocase

        // a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // https://github.com/zeze-zeze/NamedPipeMaster
        $guid_5C87B2E6_8D24_4F1D_AB85_FC659F452AD0 = "5C87B2E6-8D24-4F1D-AB85-FC659F452AD0" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_5D01A326_0357_4C3F_A196_3B8B866C9613 = "5D01A326-0357-4C3F-A196-3B8B866C9613" nocase

        // How to spoof the command line when spawning a new process from C#
        // https://github.com/plackyhacker/CmdLineSpoofer
        $guid_5D03EFC2_72E9_4410_B147_0A1A5C743999 = "5D03EFC2-72E9-4410-B147-0A1A5C743999" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_5D10ED0A_6C52_49FE_90F5_CFAAECA8FABE = "5D10ED0A-6C52-49FE-90F5-CFAAECA8FABE" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase

        // Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // https://github.com/CCob/Shwmae
        $guid_5D3EF551_3D1F_468E_A75B_764F436D577D = "5D3EF551-3D1F-468E-A75B-764F436D577D" nocase

        // SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $guid_5D4E7C1F_4812_4038_9663_6CD277ED9AD4 = "5D4E7C1F-4812-4038-9663-6CD277ED9AD4" nocase

        // Extracts passwords from a KeePass 2.x database directly from memory
        // https://github.com/denandz/KeeFarce
        $guid_5DE7F97C_B97B_489F_A1E4_9F9656317F94 = "5DE7F97C-B97B-489F-A1E4-9F9656317F94" nocase

        // Documents Exfiltration and C2 project
        // https://github.com/TheD1rkMtr/DocPlz
        $guid_5E0812A9_C727_44F3_A2E3_8286CDC3ED4F = "5E0812A9-C727-44F3-A2E3-8286CDC3ED4F" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_5E9715AB_CAF7_4FFF_8E14_A8727891DA93 = "5E9715AB-CAF7-4FFF-8E14-A8727891DA93" nocase

        // extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // https://github.com/0xsp-SRD/MDE_Enum
        $guid_5EC16C3F_1E62_4661_8C20_504CB0E55441 = "5EC16C3F-1E62-4661-8C20-504CB0E55441" nocase

        // allowing the execution of Powershell functionality without the use of Powershell.exe
        // https://github.com/PowerShellEmpire/PowerTools
        $guid_5ED2F78E_8538_4C87_BCED_E19E9DAD879C = "5ED2F78E-8538-4C87-BCED-E19E9DAD879C" nocase

        // SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // https://github.com/GhostPack/SharpDPAPI
        $guid_5F026C27_F8E6_4052_B231_8451C6A73838 = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_5F026C27_F8E6_4052_B231_8451C6A73838 = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase

        // Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // https://github.com/Imanfeng/Telemetry
        $guid_5f026c27_f8e6_4052_b231_8451c6a73838 = "5f026c27-f8e6-4052-b231-8451c6a73838" nocase

        // Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // https://github.com/Imanfeng/Telemetry
        $guid_5F026C27_F8E6_4052_B231_8451C6A73838 = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase

        // Bypassing UAC with SSPI Datagram Contexts
        // https://github.com/antonioCoco/SspiUacBypass
        $guid_5F4DC47F_7819_4528_9C16_C88F1BE97EC5 = "5F4DC47F-7819-4528-9C16-C88F1BE97EC5" nocase

        // SingleDose is a framework to build shellcode load/process injection techniques
        // https://github.com/Wra7h/SingleDose
        $guid_5FAC3991_D4FD_4227_B73D_BEE34EB89987 = "5FAC3991-D4FD-4227-B73D-BEE34EB89987" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_5FB1809B_B0FD_48E9_9E47_3CB048369433 = "5FB1809B-B0FD-48E9-9E47-3CB048369433" nocase

        // PrintNightmare exploitation
        // https://github.com/cube0x0/CVE-2021-1675
        $guid_5FEB114B_49EC_4652_B29E_8CB5E752EC3E = "5FEB114B-49EC-4652-B29E-8CB5E752EC3E" nocase

        // PrintNightmare exploitation
        // https://github.com/calebstewart/CVE-2021-1675
        $guid_5FEB114B_49EC_4652_B29E_8CB5E752EC3E = "5FEB114B-49EC-4652-B29E-8CB5E752EC3E" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_60BBE2CB_585B_4DBD_9CB9_22F00D3F11E5 = "60BBE2CB-585B-4DBD-9CB9-22F00D3F11E5" nocase

        // HTTP/S Beaconing Implant
        // https://github.com/silentbreaksec/Throwback
        $guid_60C1DA68_85AC_43AB_9A2B_27FA345EC113 = "60C1DA68-85AC-43AB-9A2B-27FA345EC113" nocase

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_60D02E32_1711_4D9E_9AC2_10627C52EB40 = "60D02E32-1711-4D9E-9AC2-10627C52EB40" nocase

        // Open-Source Remote Administration Tool For Windows C# (RAT)
        // https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $guid_619B7612_DFEA_442A_A927_D997F99C497B = "619B7612-DFEA-442A-A927-D997F99C497B" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_619B7612_DFEA_442A_A927_D997F99C497B = "619B7612-DFEA-442A-A927-D997F99C497B" nocase

        // get SYSTEM via SeImpersonate privileges
        // https://github.com/S3cur3Th1sSh1t/MultiPotato
        $guid_61CE6716_E619_483C_B535_8694F7617548 = "61CE6716-E619-483C-B535-8694F7617548" nocase

        // Windows Local Privilege Escalation from Service Account to System
        // https://github.com/antonioCoco/RoguePotato
        $guid_61CE6716_E619_483C_B535_8694F7617548 = "61CE6716-E619-483C-B535-8694F7617548" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_628E42D5_AE4F_4CDD_8D14_DAB1A3697B62 = "628E42D5-AE4F-4CDD-8D14-DAB1A3697B62" nocase

        // Adaptive DLL hijacking / dynamic export forwarding
        // https://github.com/monoxgas/Koppeling
        $guid_62E3CCF4_07F3_496E_B77D_48D5AC0E6260 = "62E3CCF4-07F3-496E-B77D-48D5AC0E6260" nocase

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_6302105A_80BB_4987_82EC_95973911238B = "6302105A-80BB-4987-82EC-95973911238B" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_630BF262_768C_4085_89B1_9FEF7375F442 = "630BF262-768C-4085-89B1-9FEF7375F442" nocase

        // A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // https://github.com/PhrozenIO/SharpFtpC2
        $guid_6376A5B0_1BA8_4854_B81E_F5DC072C0FEE = "6376A5B0-1BA8-4854-B81E-F5DC072C0FEE" nocase

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_63957210_4871_42D3_B98A_191AF5F91079 = "63957210-4871-42D3-B98A-191AF5F91079" nocase

        // WinLicense key extraction via Intel PIN
        // https://github.com/charlesnathansmith/whatlicense
        $guid_639EF517_FCFC_408E_9500_71F0DC0458DB = "639EF517-FCFC-408E-9500-71F0DC0458DB" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_63CAF2AD_A016_43BD_AA27_02CB848E2067 = "63CAF2AD-A016-43BD-AA27-02CB848E2067" nocase

        // Remote keylogger for Windows written in C++
        // https://github.com/shehzade/peeping-tom
        $guid_63ec96c5_075f_4f22_92ec_cf28a2f70737 = "63ec96c5-075f-4f22-92ec-cf28a2f70737" nocase

        // Windows rootkit designed to work with BYOVD exploits
        // https://github.com/ColeHouston/Sunder
        $guid_643ad690_5c85_4b12_af42_2d31d11657a1 = "643ad690-5c85-4b12-af42-2d31d11657a1" nocase

        // DLL and PowerShell script to assist with finding DLL hijacks
        // https://github.com/slyd0g/DLLHijackTest
        $guid_644758B1_C146_4D3B_B614_8EB6C933B0AA = "644758B1-C146-4D3B-B614-8EB6C933B0AA" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_644AFE4A_2267_4DF9_A79D_B514FB31830E = "644AFE4A-2267-4DF9-A79D-B514FB31830E" nocase

        // Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // https://github.com/peiga/DumpThatLSASS
        $guid_64D84D51_F462_4A24_85EA_845C97238C09 = "64D84D51-F462-4A24-85EA-845C97238C09" nocase

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_6536EBEC_014E_4D6B_97BE_223137694CA8 = "6536EBEC-014E-4D6B-97BE-223137694CA8" nocase

        // Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // https://github.com/GhostPack/Rubeus
        $guid_658C8B7F_3664_4A95_9572_A3E5871DFC06 = "658C8B7F-3664-4A95-9572-A3E5871DFC06" nocase

        // Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // https://github.com/GhostPack/Rubeus
        $guid_658C8B7F_3664_4A95_9572_A3E5871DFC06 = "658C8B7F-3664-4A95-9572-A3E5871DFC06" nocase

        // Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // https://github.com/rvrsh3ll/Rubeus-Rundll32
        $guid_658C8B7F_3664_4A95_9572_A3E5871DFC06 = "658C8B7F-3664-4A95-9572-A3E5871DFC06" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_658C8B7F_3664_4A95_9572_A3E5871DFC06 = "658C8B7F-3664-4A95-9572-A3E5871DFC06" nocase

        // PEASS - Privilege Escalation Awesome Scripts SUITE
        // https://github.com/carlospolop/PEASS-ng
        $guid_66AA4619_4D0F_4226_9D96_298870E9BB50 = "66AA4619-4D0F-4226-9D96-298870E9BB50" nocase

        // PEASS-ng - Privilege Escalation Awesome Scripts suite
        // https://github.com/peass-ng/PEASS-ng
        $guid_66AA4619_4D0F_4226_9D96_298870E9BB50 = "66AA4619-4D0F-4226-9D96-298870E9BB50" nocase

        // Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading
        // https://github.com/Flangvik/SharpDllProxy
        $guid_676E89F3_4785_477A_BA1C_B30340F598D5 = "676E89F3-4785-477A-BA1C-B30340F598D5" nocase

        // Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // https://github.com/Leo4j/Amnesiac
        $guid_678ce24e_70c4_47b1_b595_ca0835ba35d9 = "678ce24e-70c4-47b1-b595-ca0835ba35d9" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_6A2BA6F7_3399_4890_9453_2D5BE8EEBBA9 = "6A2BA6F7-3399-4890-9453-2D5BE8EEBBA9" nocase

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_6A3F2F04_3E48_4E21_9AB8_0CA0998A2D01 = "6A3F2F04-3E48-4E21-9AB8-0CA0998A2D01" nocase

        // collection of post-exploitation tools to gather credentials from various password managers
        // https://github.com/Slowerzs/ThievingFox
        $guid_6A5942A4_9086_408E_A9B4_05ABC34BFD58 = "6A5942A4-9086-408E-A9B4-05ABC34BFD58" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_6AA4E392_AAAF_4408_B550_85863DD4BAAF = "6AA4E392-AAAF-4408-B550-85863DD4BAAF" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_6AA4E392_AAAF_4408_B550_85863DF3BAAF = "6AA4E392-AAAF-4408-B550-85863DF3BAAF" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_6C0942A1_C852_40F4_95F9_953510BD102D = "6C0942A1-C852-40F4-95F9-953510BD102D" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_6C8ECB51_EECE_49C3_89EC_CB0AAECCFF7E = "6C8ECB51-EECE-49C3-89EC-CB0AAECCFF7E" nocase

        // Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // https://github.com/reveng007/DarkWidow
        $guid_6C9CF6A0_C098_4341_8DD1_2FCBA9594067 = "6C9CF6A0-C098-4341-8DD1-2FCBA9594067" nocase

        // PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // https://github.com/PowerShellMafia/PowerSploit
        $guid_6CAFC0C6_A428_4D30_A9F9_700E829FEA51 = "6CAFC0C6-A428-4D30-A9F9-700E829FEA51" nocase

        // An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // https://github.com/amjcyber/pwnlook
        $guid_6D663511_76E4_4D74_9B3E_191E1471C4EF = "6D663511-76E4-4D74-9B3E-191E1471C4EF" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_6DD22880_DAC5_4B4D_9C91_8C35CC7B8180 = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" nocase

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_6E0D8D5C_7B88_4C77_A347_34F8B0FD2D75 = "6E0D8D5C-7B88-4C77-A347-34F8B0FD2D75" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_6E25C93C_0985_4D6E_A4C3_89D10F4F4F5F = "6E25C93C-0985-4D6E-A4C3-89D10F4F4F5F" nocase

        //  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // https://github.com/rvrsh3ll/SharpSSDP
        $guid_6E383DE4_DE89_4247_A41A_79DB1DC03AAA = "6E383DE4-DE89-4247-A41A-79DB1DC03AAA" nocase

        // LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // https://github.com/RiccardoAncarani/LiquidSnake
        $guid_6e7645c4_32c5_4fe3_aabf_e94c2f4370e7 = "6e7645c4-32c5-4fe3-aabf-e94c2f4370e7" nocase

        // Dump the memory of a PPL with a userland exploit
        // https://github.com/itm4n/PPLdump
        $guid_6E8D2C12_255B_403C_9EF3_8A097D374DB2 = "6E8D2C12-255B-403C-9EF3-8A097D374DB2" nocase

        // Executes PowerShell from an unmanaged process
        // https://github.com/leechristensen/UnmanagedPowerShell
        $guid_6EB55FE6_C11C_453B_8B32_22B689B6B3E2 = "6EB55FE6-C11C-453B-8B32-22B689B6B3E2" nocase

        // Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // https://github.com/daem0nc0re/PrivFu
        $guid_6F99CB40_8FEF_4B63_A35D_9CEEC71F7B5F = "6F99CB40-8FEF-4B63-A35D-9CEEC71F7B5F" nocase

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_6FC09BDB_365F_4691_BBD9_CB7F69C9527A = "6FC09BDB-365F-4691-BBD9-CB7F69C9527A" nocase

        // Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // https://github.com/codesiddhant/Jasmin-Ransomware
        $guid_6FF9974C_B3C6_4EEA_8472_22BE6BD6F5CD = "6FF9974C-B3C6-4EEA-8472-22BE6BD6F5CD" nocase

        // Create a minidump of the LSASS process from memory
        // https://github.com/b4rtik/SharpMiniDump
        $guid_6FFCCF81_6C3C_4D3F_B15F_35A86D0B497F = "6FFCCF81-6C3C-4D3F-B15F-35A86D0B497F" nocase

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_70527328_DCEC_4BA7_9958_B5BC3E48CE99 = "70527328-DCEC-4BA7-9958-B5BC3E48CE99" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_70795D10_8ADF_4A4D_A584_9AB1BBF40D4B = "70795D10-8ADF-4A4D-A584-9AB1BBF40D4B" nocase

        // A small tool that can list the named pipes bound on a remote system.
        // https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $guid_70BCFFDB_AE25_4BEA_BF0E_09DF06B7DBC4 = "70BCFFDB-AE25-4BEA-BF0E-09DF06B7DBC4" nocase

        // Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // https://github.com/ewby/Mockingjay_BOF
        $guid_713724C3_2367_49FA_B03F_AB4B336FB405 = "713724C3-2367-49FA-B03F-AB4B336FB405" nocase

        // Remote keylogger for Windows written in C++
        // https://github.com/shehzade/peeping-tom
        $guid_71bda8ea_08bc_4ab1_9b40_614b167beb64 = "71bda8ea-08bc-4ab1-9b40-614b167beb64" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7219BFA2_5DA4_4608_A3FC_643B7E87E77A = "7219BFA2-5DA4-4608-A3FC-643B7E87E77A" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7223F9B2_17A2_432B_ADAC_51B1E35681DB = "7223F9B2-17A2-432B-ADAC-51B1E35681DB" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_7271AFD1_10F6_4589_95B7_3ABF98E7B2CA = "7271AFD1-10F6-4589-95B7-3ABF98E7B2CA" nocase

        // A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // https://github.com/keowu/BadRentdrv2
        $guid_727a1d04_70f4_4148_9120_d06510a62a9a = "727a1d04-70f4-4148-9120-d06510a62a9a" nocase

        // BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // https://github.com/RalfHacker/Kerbeus-BOF
        $guid_732211ae_4891_40d3_b2b6_85ebd6f5ffff = "732211ae-4891-40d3-b2b6-85ebd6f5ffff" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_73226E13_1701_424E_A4F2_3E4D575A1DD0 = "73226E13-1701-424E-A4F2-3E4D575A1DD0" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_733C37D8_858F_44EE_9D17_790F7DE9C040 = "733C37D8-858F-44EE-9D17-790F7DE9C040" nocase

        // Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // https://github.com/mandiant/DueDLLigence
        $guid_73948912_CEBD_48ED_85E2_85FCD1D4F560 = "73948912-CEBD-48ED-85E2-85FCD1D4F560" nocase

        // A C# implementation of RDPThief to steal credentials from RDP
        // https://github.com/passthehashbrowns/SharpRDPThief
        $guid_73B2C22B_C020_45B7_BF61_B48F49A2693F = "73B2C22B-C020-45B7-BF61-B48F49A2693F" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_73ECE052_4218_465D_AA2E_A2D03448BEDD = "73ECE052-4218-465D-AA2E-A2D03448BEDD" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_73EF1630_1208_43C5_9E3F_19A2923875C5 = "73EF1630-1208-43C5-9E3F-19A2923875C5" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_73F11EE8_F565_479E_8366_BD74EE467CE8 = "73F11EE8-F565-479E-8366-BD74EE467CE8" nocase

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_758DB128_9123_4E1B_A6C3_47323714123A = "758DB128-9123-4E1B-A6C3-47323714123A" nocase

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_758DB129_9123_4E1B_A6C3_47323714123A = "758DB129-9123-4E1B-A6C3-47323714123A" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_75E5F9A0_8D69_4426_9F16_4A65E941974D = "75E5F9A0-8D69-4426-9F16-4A65E941974D" nocase

        // perform S4U logon with SeTcbPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_7607CC54_D49D_4004_8B20_15555D58C842 = "7607CC54-D49D-4004-8B20-15555D58C842" nocase

        // Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // https://github.com/binderlabs/DirCreate2System
        $guid_765C5755_DBE9_4AB5_9427_921D0E46F9F0 = "765C5755-DBE9-4AB5-9427-921D0E46F9F0" nocase

        // AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // https://github.com/AutoHotkey/AutoHotkey
        $guid_76EFDEE3_81CF_4ADA_94DC_EA5509FF6FFC = "76EFDEE3-81CF-4ADA-94DC-EA5509FF6FFC" nocase

        // Basic password spraying tool for internal tests and red teaming
        // https://github.com/HunnicCyber/SharpDomainSpray
        $guid_76FFA92B_429B_4865_970D_4E7678AC34EA = "76FFA92B-429B-4865-970D-4E7678AC34EA" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_7760248F_9247_4206_BE42_A6952AA46DA2 = "7760248F-9247-4206-BE42-A6952AA46DA2" nocase

        // SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // https://github.com/cobbr/SharpSploit
        $guid_7760248F_9247_4206_BE42_A6952AA46DA2 = "7760248F-9247-4206-BE42-A6952AA46DA2" nocase

        // SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // https://github.com/cobbr/SharpSploit
        $guid_7760248F_9247_4206_BE42_A6952AA46DA2 = "7760248F-9247-4206-BE42-A6952AA46DA2" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_77612014_2E37_4E17_AAFE_9AD4F08B4263 = "77612014-2E37-4E17-AAFE-9AD4F08B4263" nocase

        // Open-Source Remote Administration Tool For Windows C# (RAT)
        // https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $guid_7767C300_5FD5_4A5D_9D4C_59559CCE48A3 = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_7767C300_5FD5_4A5D_9D4C_59559CCE48A3 = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" nocase

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_7777E837_E7A3_481B_8BD2_4C76F639ECFC = "7777E837-E7A3-481B-8BD2-4C76F639ECFC" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_77F955C3_4910_49EA_9CD4_CBF5AD9C071A = "77F955C3-4910-49EA-9CD4-CBF5AD9C071A" nocase

        // Timestomp Tool to flatten MAC times with a specific timestamp
        // https://github.com/ZephrFish/Stompy
        $guid_784F8029_4D72_4363_9638_5A8D11545494 = "784F8029-4D72-4363-9638-5A8D11545494" nocase

        // Undetectable Payload Generator Tool
        // https://github.com/1y0n/AV_Evasion_Tool
        $guid_7898617D_08D2_4297_ADFE_5EDD5C1B828B = "7898617D-08D2-4297-ADFE-5EDD5C1B828B" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_78BB6D02_6E02_4933_89DC_4AD8EE0B303F = "78BB6D02-6E02-4933-89DC-4AD8EE0B303F" nocase

        // Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // https://github.com/codesiddhant/Jasmin-Ransomware
        $guid_78C76961_8249_4EFE_9DE2_B6EF15A187F7 = "78C76961-8249-4EFE-9DE2-B6EF15A187F7" nocase

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_78DE9716_84E8_4469_A5AE_F3E43181C28B = "78DE9716-84E8-4469-A5AE-F3E43181C28B" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_78EB3006_81B0_4C13_9B80_E91766874A57 = "78EB3006-81B0-4C13-9B80-E91766874A57" nocase

        // A C# implementation of dumping credentials from Windows Credential Manager
        // https://github.com/leftp/BackupCreds
        $guid_7943C5FF_C219_4E0B_992E_0ECDEB2681F3 = "7943C5FF-C219-4E0B-992E-0ECDEB2681F3" nocase

        // control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // https://gitlab.com/KevinJClark/badrats
        $guid_79520C3A_4931_46EB_92D7_334DA7FC9013 = "79520C3A-4931-46EB-92D7-334DA7FC9013" nocase

        // SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // https://github.com/GhostPack/SharpDump
        $guid_79C9BBA3_A0EA_431C_866C_77004802D8A0 = "79C9BBA3-A0EA-431C-866C-77004802D8A0" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_79C9BBA3_A0EA_431C_866C_77004802D8A0 = "79C9BBA3-A0EA-431C-866C-77004802D8A0" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_79D3788D_683D_4799_94B7_00360F08145B = "79D3788D-683D-4799-94B7-00360F08145B" nocase

        // Abuses the Windows containers framework to bypass EDRs.
        // https://github.com/deepinstinct/ContainYourself
        $guid_79F54747_048D_4FD6_AEF4_7B098F923FD8 = "79F54747-048D-4FD6-AEF4-7B098F923FD8" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7A58EE54_7F2E_4C2F_B41E_19DD0D1629F1 = "7A58EE54-7F2E-4C2F-B41E-19DD0D1629F1" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7A6CEC00_4A6C_45E0_A25D_3CAB2F436EA6 = "7A6CEC00-4A6C-45E0-A25D-3CAB2F436EA6" nocase

        // A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // https://github.com/ihamburglar/fgdump
        $guid_7A87DEAE_7B94_4986_9294_BD69B12A9732 = "7A87DEAE-7B94-4986-9294-BD69B12A9732" nocase

        // Injects a DLL into a suspended process running as SYSTEM via the OfficeClickToRun service for privilege escalation - Shim Injector: Injects a DLL into a process by modifying shim data in memory without creating or registering new SDB files to evade detection.
        // https://github.com/deepinstinct/ShimMe
        $guid_7afe06b8_59cc_41d2_9d75_65473ea93117 = "7afe06b8-59cc-41d2-9d75-65473ea93117" nocase

        // Persistence by writing/reading shellcode from Event Log
        // https://github.com/improsec/SharpEventPersist
        $guid_7B4D3810_4A77_44A1_8546_779ACF02D083 = "7B4D3810-4A77-44A1-8546-779ACF02D083" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7BCD7440_845C_417B_8C2F_AA89D3AE8FD0 = "7BCD7440-845C-417B-8C2F-AA89D3AE8FD0" nocase

        // DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // https://github.com/deepinstinct/DCOMUploadExec
        $guid_7bf6b6be_a29f_440a_9962_9fabc5d9665a = "7bf6b6be-a29f-440a-9962-9fabc5d9665a" nocase

        // An open-source windows defender manager. Now you can disable windows defender permanently
        // https://github.com/pgkt04/defender-control
        $guid_7c2c0aec_7b9d_4104_99fa_1844d609452c = "7c2c0aec-7b9d-4104-99fa-1844d609452c" nocase

        // allowing the execution of Powershell functionality without the use of Powershell.exe
        // https://github.com/PowerShellEmpire/PowerTools
        $guid_7C3D26E5_0A61_479A_AFAC_D34F2659F301 = "7C3D26E5-0A61-479A-AFAC-D34F2659F301" nocase

        // Complete exploit works on vulnerable Windows 11 22H2 systems CVE-2023-36802 Local Privilege Escalation POC
        // https://github.com/chompie1337/Windows_MSKSSRV_LPE_CVE-2023-36802
        $guid_7C5C471B_9630_4DF5_A099_405D86553ECA = "7C5C471B-9630-4DF5-A099-405D86553ECA" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_7C6D1CCD_D4DF_426A_B5D6_A6B5F13D0091 = "7C6D1CCD-D4DF-426A-B5D6-A6B5F13D0091" nocase

        // Hide your P/Invoke signatures through other people's signed assemblies
        // https://github.com/MzHmO/Parasite-Invoke
        $guid_7CEC7793_3E22_455B_9E88_94B8D1A8F78D = "7CEC7793-3E22-455B-9E88-94B8D1A8F78D" nocase

        // perform the RottenPotato attack and get a handle to a privileged token
        // https://github.com/breenmachine/RottenPotatoNG
        $guid_7E1BCC8E_F61C_4728_BB8A_28FB42928256 = "7E1BCC8E-F61C-4728-BB8A-28FB42928256" nocase

        // EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // https://github.com/wavestone-cdt/EDRSandblast
        $guid_7E3E2ECE_D1EB_43C6_8C83_B52B7571954B = "7E3E2ECE-D1EB-43C6-8C83-B52B7571954B" nocase

        // Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // https://github.com/gabriellandau/EDRSandblast-GodFault
        $guid_7E3E2ECE_D1EB_43C6_8C83_B52B7571954B = "7E3E2ECE-D1EB-43C6-8C83-B52B7571954B" nocase

        // A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // https://github.com/ShorSec/ShadowSpray
        $guid_7E47D586_DDC6_4382_848C_5CF0798084E1 = "7E47D586-DDC6-4382-848C-5CF0798084E1" nocase

        // A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // https://github.com/Dec0ne/ShadowSpray
        $guid_7E47D586_DDC6_4382_848C_5CF0798084E1 = "7E47D586-DDC6-4382-848C-5CF0798084E1" nocase

        // Crassus Windows privilege escalation discovery tool
        // https://github.com/vu-ls/Crassus
        $guid_7E9729AA_4CF2_4D0A_8183_7FB7CE7A5B1A = "7E9729AA-4CF2-4D0A-8183-7FB7CE7A5B1A" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7EAE7E78_ED95_4CAB_B3B3_231B41BB5AA0 = "7EAE7E78-ED95-4CAB-B3B3-231B41BB5AA0" nocase

        // Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // https://github.com/binderlabs/DirCreate2System
        $guid_7EE536AE_6C1D_4881_88F7_37C8F2A0CA50 = "7EE536AE-6C1D-4881-88F7-37C8F2A0CA50" nocase

        // Bypass antivirus software to add users
        // https://github.com/TryA9ain/BypassAddUser
        $guid_7FDCF4E0_2E6A_43D5_80FB_0A1A40AB3D93 = "7FDCF4E0-2E6A-43D5-80FB-0A1A40AB3D93" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_8026261f_ac68_4ccf_97b2_3b55b7d6684d = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" nocase

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_80BA63A4_7D41_40E9_A722_6DD58B28BF7E = "80BA63A4-7D41-40E9-A722-6DD58B28BF7E" nocase

        // enabling Recall in Windows 11 version 24H2 on unsupported devices
        // https://github.com/thebookisclosed/AmperageKit
        $guid_80C7245C_B926_4CEB_BA5B_5353736137A8 = "80C7245C-B926-4CEB-BA5B-5353736137A8" nocase

        // Winsock accept() Backdoor Implant
        // https://github.com/EgeBalci/WSAAcceptBackdoor
        $guid_811683b1_e01c_4ef8_82d1_aa08293d3e7c = "811683b1-e01c-4ef8-82d1-aa08293d3e7c" nocase

        // Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // https://github.com/WithSecureLabs/physmem2profit
        $guid_814708C9_2320_42D2_A45F_31E42DA06A94 = "814708C9-2320-42D2-A45F-31E42DA06A94" nocase

        // Cross-platform multi-protocol VPN software abused by attackers
        // https://github.com/SoftEtherVPN/SoftEtherVPN
        $guid_81CA3EC4_026E_4D37_9889_828186BBB8C0 = "81CA3EC4-026E-4D37-9889-828186BBB8C0" nocase

        // Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // https://github.com/SaadAhla/UnhookingPatch
        $guid_81E60DC6_694E_4F51_88FA_6F481B9A4208 = "81E60DC6-694E-4F51-88FA-6F481B9A4208" nocase

        // Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // https://github.com/TheD1rkMtr/UnhookingPatch
        $guid_81E60DC6_694E_4F51_88FA_6F481B9A4208 = "81E60DC6-694E-4F51-88FA-6F481B9A4208" nocase

        // Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // https://github.com/TheD1rkMtr/FilelessPELoader
        $guid_82277B35_D159_4B44_8D54_FB66EDD58D5C = "82277B35-D159-4B44-8D54-FB66EDD58D5C" nocase

        // Microsoft Graph API post-exploitation toolkit
        // https://github.com/mlcsec/SharpGraphView
        $guid_825E2088_EC7C_4AB0_852A_4F1FEF178E37 = "825E2088-EC7C-4AB0-852A-4F1FEF178E37" nocase

        // Patching signtool.exe to accept expired certificates for code-signing
        // https://github.com/hackerhouse-opensource/SignToolEx
        $guid_82B0EE92_347E_412F_8EA2_CBDE683EDA57 = "82B0EE92-347E-412F-8EA2-CBDE683EDA57" nocase

        // open source ransomware - many variant in the wild
        // https://github.com/goliate/hidden-tear
        $guid_82C19CBA_E318_4BB3_A408_5005EA083EC5 = "82C19CBA-E318-4BB3-A408-5005EA083EC5" nocase

        // A red team tool that assists into extracting/dumping master credentials and/or entries from different password managers
        // https://github.com/efchatz/pandora
        $guid_82F417BE_49BF_44FF_9BBD_64FECEA181D7 = "82F417BE-49BF-44FF-9BBD-64FECEA181D7" nocase

        // Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // https://github.com/TheD1rkMtr/HeapCrypt
        $guid_83035080_7788_4EA3_82EE_6C06D2E6891F = "83035080-7788-4EA3-82EE-6C06D2E6891F" nocase

        // in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // https://github.com/riskydissonance/SafetyDump
        $guid_8347E81B_89FC_42A9_B22C_F59A6A572DEC = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase

        // SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // https://github.com/GhostPack/SafetyKatz
        $guid_8347E81B_89FC_42A9_B22C_F59A6A572DEC = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_8347E81B_89FC_42A9_B22C_F59A6A572DEC = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase

        // abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // https://github.com/trustedsec/The_Shelf
        $guid_83DF0D0B_8FC6_4BCA_9982_4D26523515A2 = "83DF0D0B-8FC6-4BCA-9982-4D26523515A2" nocase

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_8425D05F_F3F4_4132_9BE1_BED752685333 = "8425D05F-F3F4-4132-9BE1-BED752685333" nocase

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_847D29FF_8BBC_4068_8BE1_D84B1089B3C0 = "847D29FF-8BBC-4068-8BE1-D84B1089B3C0" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_8489A9CE_AB1A_4D8D_8824_D9E18B9945FE = "8489A9CE-AB1A-4D8D-8824-D9E18B9945FE" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_8493D0F0_CA01_4C5A_A6E3_C0F427966ABD = "8493D0F0-CA01-4C5A-A6E3-C0F427966ABD" nocase

        // Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // https://github.com/gitjdm/dumper2020
        $guid_84A7E50E_B0F0_4B3D_98CD_F32CDB1EB8CA = "84A7E50E-B0F0-4B3D-98CD-F32CDB1EB8CA" nocase

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_8558952E_C76B_4976_949F_76A977DA7F8A = "8558952E-C76B-4976-949F-76A977DA7F8A" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_862DA0DA_52E1_47CD_B9C2_46B106031B28 = "862DA0DA-52E1-47CD-B9C2-46B106031B28" nocase

        // Find vulnerabilities in AD Group Policy
        // https://github.com/Group3r/Group3r
        $guid_868A6C76_C903_4A94_96FD_A2C6BA75691C = "868A6C76-C903-4A94-96FD-A2C6BA75691C" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_86F8C733_F773_4AD8_9282_3F99953261FD = "86F8C733-F773-4AD8-9282-3F99953261FD" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_86FC4B74_3B12_4C72_AA6C_084BF98E5E9A = "86FC4B74-3B12-4C72-AA6C-084BF98E5E9A" nocase

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_86FF6D04_208C_442F_B27C_E4255DD39402 = "86FF6D04-208C-442F-B27C-E4255DD39402" nocase

        // steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // https://github.com/shaddy43/BrowserSnatch
        $guid_87440f0b_dacf_4695_a483_031fdc0b0194 = "87440f0b-dacf-4695-a483-031fdc0b0194" nocase

        // Command and Control Framework written in C#
        // https://github.com/rasta-mouse/SharpC2
        $guid_87904247_C363_4F12_A13A_3DA484913F9E = "87904247-C363-4F12-A13A-3DA484913F9E" nocase

        // A tool for pointesters to find candies in SharePoint
        // https://github.com/nheiniger/SnaffPoint
        $guid_879A49C7_0493_4235_85F6_EBF962613A76 = "879A49C7-0493-4235-85F6-EBF962613A76" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_87BEF4D7_813E_48BA_96FE_E3A24BF2DC34 = "87BEF4D7-813E-48BA-96FE-E3A24BF2DC34" nocase

        // UAC Bypass By Abusing Kerberos Tickets
        // https://github.com/wh0amitz/KRBUACBypass
        $guid_881D4D67_46DD_4F40_A813_C9D3C8BE0965 = "881D4D67-46DD-4F40-A813-C9D3C8BE0965" nocase

        // Escalate Service Account To LocalSystem via Kerberos
        // https://github.com/wh0amitz/S4UTomato
        $guid_881D4D67_46DD_4F40_A813_C9D3C8BE0965 = "881D4D67-46DD-4F40-A813-C9D3C8BE0965" nocase

        // UAC bypass for x64 Windows 7 - 11
        // https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $guid_8845A8AF_34DC_4EBC_8223_B35F8CC8A900 = "8845A8AF-34DC-4EBC-8223-B35F8CC8A900" nocase

        // .NET HttpClient proxy handler implementation for SOCKS proxies
        // https://github.com/bbepis/Nsocks
        $guid_889E3D8B_58FA_462D_A2D8_3CB430484B6A = "889E3D8B-58FA-462D-A2D8-3CB430484B6A" nocase

        // Shellcode Loader with memory evasion
        // https://github.com/RtlDallas/Jomungand
        $guid_88B40068_B3DB_4C2F_86F9_8EADC52CFE58 = "88B40068-B3DB-4C2F-86F9-8EADC52CFE58" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_8923E1ED_2594_4668_A4FA_DC2CFF7EA1CA = "8923E1ED-2594-4668-A4FA-DC2CFF7EA1CA" nocase

        // Potato Privilege Escalation on Windows
        // https://github.com/foxglovesec/Potato
        $guid_893CC775_335D_4010_9751_D8C8E2A04048 = "893CC775-335D-4010-9751-D8C8E2A04048" nocase

        // SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // https://github.com/BeichenDream/SharpToken
        $guid_894a784e_e04c_483c_a762_b6c03e744d0b = "894a784e-e04c-483c-a762-b6c03e744d0b" nocase

        // SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // https://github.com/BeichenDream/SharpToken
        $guid_894A784E_E04C_483C_A762_B6C03E744D0B = "894A784E-E04C-483C-A762-B6C03E744D0B" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_8A15D28C_252A_4FCC_8BBD_BC3802C0320A = "8A15D28C-252A-4FCC-8BBD-BC3802C0320A" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_8A516D69_BA38_429F_AFFE_C571B5C1E482 = "8A516D69-BA38-429F-AFFE-C571B5C1E482" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_8b1f0a69_a930_42e3_9c13_7de0d04a4add = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_8B605B2E_AAD2_46FB_A348_27E3AABA4C9C = "8B605B2E-AAD2-46FB-A348-27E3AABA4C9C" nocase

        // execute process as NT SERVICE\TrustedInstaller group account
        // https://github.com/daem0nc0re/PrivFu
        $guid_8B723CB2_017A_4CB6_B3E6_C26E9F1F8B3C = "8B723CB2-017A-4CB6-B3E6-C26E9F1F8B3C" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_8B73C3EC_D0C4_4E0D_843A_67C81283EC5F = "8B73C3EC-D0C4-4E0D-843A-67C81283EC5F" nocase

        // AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // https://github.com/RythmStick/AMSITrigger
        $guid_8BAAEFF6_1840_4430_AA05_47F2877E3235 = "8BAAEFF6-1840-4430-AA05-47F2877E3235" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_8BF244EB_0CA3_403E_A076_F1D77731A728 = "8BF244EB-0CA3-403E-A076-F1D77731A728" nocase

        // a tool to help operate in EDRs' blind spots
        // https://github.com/naksyn/Pyramid
        $guid_8BF82BBE_909C_4777_A2FC_EA7C070FF43E = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase

        // .NET Project for performing Authenticated Remote Execution
        // https://github.com/0xthirteen/SharpMove
        $guid_8BF82BBE_909C_4777_A2FC_EA7C070FF43E = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_8BFC8ED2_71CC_49DC_9020_2C8199BC27B6 = "8BFC8ED2-71CC-49DC-9020-2C8199BC27B6" nocase

        // Injects a DLL into a suspended process running as SYSTEM via the OfficeClickToRun service for privilege escalation - Shim Injector: Injects a DLL into a process by modifying shim data in memory without creating or registering new SDB files to evade detection.
        // https://github.com/deepinstinct/ShimMe
        $guid_8cb4a31c_11c4_49e4_8c7a_b9c6df93f5d8 = "8cb4a31c-11c4-49e4-8c7a-b9c6df93f5d8" nocase

        // Remote Command Executor: A OSS replacement for PsExec and RunAs
        // https://github.com/kavika13/RemCom
        $guid_8CC59FFA_00E0_0AEA_59E8_E780672C3CB3 = "8CC59FFA-00E0-0AEA-59E8-E780672C3CB3" nocase

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_8D907846_455E_39A7_BD31_BC9F81468B47 = "8D907846-455E-39A7-BD31-BC9F81468B47" nocase

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_8D907846_455E_39A7_BD31_BC9F81468B47 = "8D907846-455E-39A7-BD31-BC9F81468B47" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_8dac9832_d464_4916_b102_9efa913bdc44 = "8dac9832-d464-4916-b102-9efa913bdc44" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_8DE42DA3_BE99_4E7E_A3D2_3F65E7C1ABCE = "8DE42DA3-BE99-4E7E-A3D2-3F65E7C1ABCE" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_8DED0EC8_3611_4481_88FC_14B82531FD2B = "8DED0EC8-3611-4481-88FC-14B82531FD2B" nocase

        // Recovering NTLM hashes from Credential Guard
        // https://github.com/ly4k/PassTheChallenge
        $guid_8F018213_4136_4D97_9084_F0346BBED04F = "8F018213-4136-4D97-9084-F0346BBED04F" nocase

        // enable or disable specific token privileges for a process
        // https://github.com/daem0nc0re/PrivFu
        $guid_8F208DB9_7555_46D5_A5FE_2D7E85E05CAA = "8F208DB9-7555-46D5-A5FE-2D7E85E05CAA" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_8F71C671_F53C_4F4F_98B9_8B8D3263C0DB = "8F71C671-F53C-4F4F-98B9-8B8D3263C0DB" nocase

        // MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // https://github.com/Xre0uS/MultiDump
        $guid_90229D7D_5CC2_4C1E_80D3_4B7C7289B480 = "90229D7D-5CC2-4C1E-80D3-4B7C7289B480" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_9042B543_13D1_42B3_A5B6_5CC9AD55E150 = "9042B543-13D1-42B3-A5B6-5CC9AD55E150" nocase

        // C# Data Collector for BloodHound
        // https://github.com/BloodHoundAD/SharpHound
        $guid_90A6822C_4336_433D_923F_F54CE66BA98F = "90A6822C-4336-433D-923F-F54CE66BA98F" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_90DEB964_F2FB_4DB8_9BCA_7D5D10D3A0EB = "90DEB964-F2FB-4DB8-9BCA-7D5D10D3A0EB" nocase

        // tool written in C# that aims to do enumeration via LDAP queries
        // https://github.com/mertdas/SharpLDAP
        $guid_90F6244A_5EEE_4A7A_8C75_FA6A52DF34D3 = "90F6244A-5EEE-4A7A-8C75-FA6A52DF34D3" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_91B12706_DC6A_45DE_97F1_FAF0901FF6AF = "91B12706-DC6A-45DE-97F1-FAF0901FF6AF" nocase

        // Command and Control Framework written in C#
        // https://github.com/rasta-mouse/SharpC2
        $guid_91EA50CD_E8DF_4EDF_A765_75354643BD0D = "91EA50CD-E8DF-4EDF-A765-75354643BD0D" nocase

        // Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // https://github.com/b4rtik/ATPMiniDump
        $guid_920B8C5B_0DC5_4BD7_B6BB_D14B39BFC9FE = "920B8C5B-0DC5-4BD7-B6BB-D14B39BFC9FE" nocase

        // mimikatz UUID
        // https://github.com/gentilkiwi/mimikatz
        $guid_921BB3E1_15EE_4bbe_83D4_C4CE176A481B = "921BB3E1-15EE-4bbe-83D4-C4CE176A481B" nocase

        // WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // https://github.com/pwn1sher/WMEye
        $guid_928120DC_5275_4806_B99B_12D67B710DC0 = "928120DC-5275-4806-B99B-12D67B710DC0" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_92C5208E_DE76_49F9_B022_1A558C95B6DF = "92C5208E-DE76-49F9-B022-1A558C95B6DF" nocase

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_9341205B_AEE0_483B_9A80_975C2084C3AE = "9341205B-AEE0-483B-9A80-975C2084C3AE" nocase

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_935D33C5_62F1_40FE_8DB0_46B6E01342FB = "935D33C5-62F1-40FE-8DB0-46B6E01342FB" nocase

        // Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // https://github.com/XaFF-XaFF/Cronos-Rootkit
        $guid_940B1177_2B8C_48A2_A8E7_BF4E8E80C60F = "940B1177-2B8C-48A2-A8E7-BF4E8E80C60F" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_9434E131_51CD_4FC6_9105_D73734DC5BA6 = "9434E131-51CD-4FC6-9105-D73734DC5BA6" nocase

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_946619C2_5959_4C0C_BC7C_1C27D825B042 = "946619C2-5959-4C0C-BC7C-1C27D825B042" nocase

        // Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // https://github.com/reveng007/SharpGmailC2
        $guid_946D24E4_201B_4D51_AF9A_3190266E0E1B = "946D24E4-201B-4D51-AF9A-3190266E0E1B" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_94AEDCE4_D4A2_45DB_B98E_860EE6BE8385 = "94AEDCE4-D4A2-45DB-B98E-860EE6BE8385" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_94DE5045_4D09_437B_BDE3_679FCAF07A2D = "94DE5045-4D09-437B-BDE3-679FCAF07A2D" nocase

        // alternative to the Cobalt Strike Beacon
        // https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon
        $guid_95502b5e_5763_4ec5_a64c_1e9e33409e2f = "95502b5e-5763-4ec5-a64c-1e9e33409e2f" nocase

        // Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // https://github.com/zer0condition/ZeroHVCI
        $guid_95529189_2fb6_49e4_ab2d_3c925ada4414 = "95529189-2fb6-49e4-ab2d-3c925ada4414" nocase

        // C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // https://github.com/Hagrid29/DumpAADSyncCreds
        $guid_95A40D7C_F3F7_4C45_8C5A_D384DE50B6C9 = "95A40D7C-F3F7-4C45-8C5A-D384DE50B6C9" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_95BB9D5E_260F_4A70_B0FA_0757A94EF677 = "95BB9D5E-260F-4A70-B0FA-0757A94EF677" nocase

        // Adaptive DLL hijacking / dynamic export forwarding
        // https://github.com/monoxgas/Koppeling
        $guid_95BC2C38_1FBE_4AF1_967E_BC133250C4D4 = "95BC2C38-1FBE-4AF1-967E-BC133250C4D4" nocase

        // Leverage a legitimate WFP callout driver to prevent EDR agents from sending telemetry
        // https://github.com/senzee1984/EDRPrison
        $guid_9674DF71_0814_4398_8A77_5A32A8CBE61E = "9674DF71-0814-4398-8A77-5A32A8CBE61E" nocase

        // This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // https://github.com/passthehashbrowns/SharpBuster
        $guid_9786E418_6C4A_471D_97C0_8B5F2ED524C8 = "9786E418-6C4A-471D-97C0-8B5F2ED524C8" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_97C056B0_2AEB_4467_AAC9_E0FE0639BA9E = "97C056B0-2AEB-4467-AAC9-E0FE0639BA9E" nocase

        // A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // https://github.com/bats3c/ADCSPwn
        $guid_980EF05F_87D1_4A0A_932A_582FB1BC3AC3 = "980EF05F-87D1-4A0A-932A-582FB1BC3AC3" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_99142A50_E046_4F18_9C52_9855ABADA9B3 = "99142A50-E046-4F18-9C52-9855ABADA9B3" nocase

        // Windows Antivirus Comparison and Patch Number Comparison
        // https://github.com/uknowsec/SharpAVKB
        $guid_99DDC600_3E6F_435E_89DF_74439FA68061 = "99DDC600-3E6F-435E-89DF-74439FA68061" nocase

        // The OpenBullet web testing application.
        // https://github.com/openbullet/openbullet
        $guid_99E40E7F_00A4_4FB1_9441_B05A56C47C08 = "99E40E7F-00A4-4FB1-9441-B05A56C47C08" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_9A374E66_70B5_433D_8D7D_89E3F8AC0617 = "9A374E66-70B5-433D-8D7D-89E3F8AC0617" nocase

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_9AA32BBF_90F3_4CE6_B210_CBCDB85052B0 = "9AA32BBF-90F3-4CE6-B210-CBCDB85052B0" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_9B823D93_BF1B_407B_A4CD_231347F656AD = "9B823D93-BF1B-407B-A4CD-231347F656AD" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_9C30CAE4_6FBE_45CC_90C2_1D739DB92E86 = "9C30CAE4-6FBE-45CC-90C2-1D739DB92E86" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_9CCE5C71_14B4_4A08_958D_4E593975658B = "9CCE5C71-14B4-4A08-958D-4E593975658B" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_9CFD5FA4_5AD6_463C_87E5_3F42133B5DA8 = "9CFD5FA4-5AD6-463C-87E5-3F42133B5DA8" nocase

        // SharPersist Windows persistence toolkit written in C#.
        // https://github.com/fireeye/SharPersist
        $guid_9D1B853E_58F1_4BA5_AEFC_5C221CA30E48 = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_9D1D39D8_2387_46ED_A4A8_59D250C97F35 = "9D1D39D8-2387-46ED-A4A8-59D250C97F35" nocase

        // Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // https://github.com/TheD1rkMtr/NTDLLReflection
        $guid_9D365106_D7B8_4B5E_82CC_6D6ABCDCA2B8 = "9D365106-D7B8-4B5E-82CC-6D6ABCDCA2B8" nocase

        // Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // https://github.com/OG-Sadpanda/SharpSword
        $guid_9E357027_8AA6_4376_8146_F5AF610E14BB = "9E357027-8AA6-4376-8146-F5AF610E14BB" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_9E36AE6E_B9FD_4B9B_99BA_42D3EACD7506 = "9E36AE6E-B9FD-4B9B-99BA-42D3EACD7506" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_9E5A6F99_0A26_4959_847D_A4221CF4441B = "9E5A6F99-0A26-4959-847D-A4221CF4441B" nocase

        // Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // https://github.com/ricardojoserf/TrickDump
        $guid_9E9BB94C_1FBE_4D0B_83B7_E42C83FC5D45 = "9E9BB94C-1FBE-4D0B-83B7-E42C83FC5D45" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_9EB8DC3B_60DC_451E_8C18_3D7E38D463FD = "9EB8DC3B-60DC-451E-8C18-3D7E38D463FD" nocase

        // A C# tool to dump all sorts of goodies from AD FS
        // https://github.com/mandiant/ADFSDump
        $guid_9EE27D63_6AC9_4037_860B_44E91BAE7F0D = "9EE27D63-6AC9-4037-860B-44E91BAE7F0D" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_9EFFFF7A_DC03_4D52_BB8F_F0140FAD26E7 = "9EFFFF7A-DC03-4D52-BB8F-F0140FAD26E7" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_9F5CF56A_DDB2_4F40_AB99_2A1DC47588E1 = "9F5CF56A-DDB2-4F40-AB99-2A1DC47588E1" nocase

        // Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // https://github.com/quasar/Quasar
        $guid_9F5CF56A_DDB2_4F40_AB99_2A1DC47588E1 = "9F5CF56A-DDB2-4F40-AB99-2A1DC47588E1" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_9FEA6712_3880_4E5F_BD56_8E58A4EBCCB4 = "9FEA6712-3880-4E5F-BD56-8E58A4EBCCB4" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_A017568E_B62E_46B4_9557_15B278656365 = "A017568E-B62E-46B4-9557-15B278656365" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_A0E096FB_3AEF_41B5_A67B_BD90D2FEBBFC = "A0E096FB-3AEF-41B5-A67B-BD90D2FEBBFC" nocase

        // A tool to kill antimalware protected processes
        // https://github.com/Yaxser/Backstab
        $guid_A0E7B538_F719_47B8_8BE4_A82C933F5753 = "A0E7B538-F719-47B8-8BE4-A82C933F5753" nocase

        // TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // https://github.com/Flangvik/TeamFiltration
        $guid_A0F044C5_D910_4720_B082_58824E372281 = "A0F044C5-D910-4720-B082-58824E372281" nocase

        // leverages the NetUserAdd Win32 API to create a new computer account
        // https://github.com/Ben0xA/DoUCMe
        $guid_A11E7DAE_21F2_46A8_991E_D38DEBE1650F = "A11E7DAE-21F2-46A8-991E-D38DEBE1650F" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_A138FC2A_7BFF_4B3C_94A0_62A8BC01E8C0 = "A138FC2A-7BFF-4B3C-94A0-62A8BC01E8C0" nocase

        // Run Powershell without software restrictions.
        // https://github.com/iomoath/PowerShx
        $guid_A17656B2_42D1_42CD_B76D_9B60F637BCB5 = "A17656B2-42D1-42CD-B76D-9B60F637BCB5" nocase

        // Shim database persistence (Fin7 TTP)
        // https://github.com/jackson5sec/ShimDB
        $guid_A1A949A4_5CE4_4FCF_A3B9_A2290EA46086 = "A1A949A4-5CE4-4FCF-A3B9-A2290EA46086" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_A1F54816_3FBA_4A71_9D26_D31C6BE9CF01 = "A1F54816-3FBA-4A71-9D26-D31C6BE9CF01" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_A2107C86_7CB5_45EE_89E8_1BC7261F7762 = "A2107C86-7CB5-45EE-89E8-1BC7261F7762" nocase

        // Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $guid_A220F564_41CB_46F5_9938_FEFD87819771 = "A220F564-41CB-46F5-9938-FEFD87819771" nocase

        // Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // https://github.com/wh0amitz/PetitPotato
        $guid_A315E53B_397A_4074_B988_535A100D45DC = "A315E53B-397A-4074-B988-535A100D45DC" nocase

        // inspect token information
        // https://github.com/daem0nc0re/PrivFu
        $guid_A318BEE3_2BDB_41A1_BE56_956774BBC12B = "A318BEE3-2BDB-41A1-BE56-956774BBC12B" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_a336f517_bca9_465f_8ff8_2756cfd0cad9 = "a336f517-bca9-465f-8ff8-2756cfd0cad9" nocase

        // enabling Recall in Windows 11 version 24H2 on unsupported devices
        // https://github.com/thebookisclosed/AmperageKit
        $guid_A3454AF1_12AF_4952_B26D_FF0930DB779E = "A3454AF1-12AF-4952-B26D-FF0930DB779E" nocase

        // DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // https://github.com/DavidXanatos/DiskCryptor
        $guid_A38C04C7_B172_4897_8471_E3478903035E = "A38C04C7-B172-4897-8471-E3478903035E" nocase

        // DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // https://github.com/DavidXanatos/DiskCryptor
        $guid_A38C04C7_B172_4897_8471_E3478903035E = "A38C04C7-B172-4897-8471-E3478903035E" nocase

        // Metasploit is a widely-used. open-source framework designed for penetration testing. vulnerability assessment. and exploit development. It provides security professionals and researchers with a comprehensive platform to discover. exploit. and validate vulnerabilities in computer systems and networks. Metasploit includes a large database of pre-built exploits. payloads. and auxiliary modules that can be used to test various attack vectors. identify security weaknesses. and simulate real-world cyberattacks. By utilizing Metasploit. security teams can better understand potential threats and improve their overall security posture.
        // https://github.com/rapid7/metasploit-omnibus
        $guid_A3C83F57_6D8F_453A_9559_0D650A95EB21 = "A3C83F57-6D8F-453A-9559-0D650A95EB21" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_A45C184F_F98F_4258_A928_BFF437034791 = "A45C184F-F98F-4258-A928-BFF437034791" nocase

        // Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // https://github.com/exploits-forsale/prefetch-tool
        $guid_A46C9A13_145E_42C0_8CA6_CC920BF1D9F1 = "A46C9A13-145E-42C0-8CA6-CC920BF1D9F1" nocase

        // C# Data Collector for BloodHound
        // https://github.com/BloodHoundAD/SharpHound
        $guid_A517A8DE_5834_411D_ABDA_2D0E1766539C = "A517A8DE-5834-411D-ABDA-2D0E1766539C" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_A5B912EC_D588_401C_A84F_D01F98142B9E = "A5B912EC-D588-401C-A84F-D01F98142B9E" nocase

        // AV/EDR evasion
        // https://github.com/myzxcg/RealBlindingEDR
        $guid_A62776D0_CF96_4067_B4BE_B337AB6DFF02 = "A62776D0-CF96-4067-B4BE-B337AB6DFF02" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_A6497C83_7DC7_4E48_87BA_FB5DFAABE3C9 = "A6497C83-7DC7-4E48-87BA-FB5DFAABE3C9" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_A64EF001_BE90_4CF5_86B2_22DFDB49AE81 = "A64EF001-BE90-4CF5-86B2-22DFDB49AE81" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_A663D4C5_BC01_42A6_9C65_52F0524B4AB7 = "A663D4C5-BC01-42A6-9C65-52F0524B4AB7" nocase

        // get current user credentials by popping a fake Windows lock screen
        // https://github.com/Pickfordmatt/SharpLocker
        $guid_A6F8500F_68BC_4EFC_962A_6C6E68D893AF = "A6F8500F-68BC-4EFC-962A-6C6E68D893AF" nocase

        // Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // https://github.com/itm4n/Perfusion
        $guid_A7397316_0AEF_4379_B285_C276DE02BDE1 = "A7397316-0AEF-4379-B285-C276DE02BDE1" nocase

        // gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $guid_A7AD39B5_9BA1_48A9_B928_CA25FDD8F31F = "A7AD39B5-9BA1-48A9-B928-CA25FDD8F31F" nocase

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_A8FE1F5C_6B2A_4417_907F_4F6EDE9C15A3 = "A8FE1F5C-6B2A-4417-907F-4F6EDE9C15A3" nocase

        // Lockless allows for the copying of locked files.
        // https://github.com/GhostPack/Lockless
        $guid_A91421CB_7909_4383_BA43_C2992BBBAC22 = "A91421CB-7909-4383-BA43-C2992BBBAC22" nocase

        // prompt a user for credentials using a Windows credential dialog
        // https://github.com/ryanmrestivo/red-team/blob/1e53b7aa77717a22c9bd54facc64155a9a4c49fc/Exploitation-Tools/OffensiveCSharp/CredPhisher
        $guid_A9386992_CFAC_468A_BD41_78382212E5B9 = "A9386992-CFAC-468A-BD41-78382212E5B9" nocase

        // Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // https://github.com/sfewer-r7/CVE-2023-27532
        $guid_A96C7C34_5791_43CF_9F8B_8EF5B3FB6EBA = "A96C7C34-5791-43CF-9F8B-8EF5B3FB6EBA" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_A9EAA820_EC72_4052_80D0_A2CCBFCC83E6 = "A9EAA820-EC72-4052-80D0-A2CCBFCC83E6" nocase

        // SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // https://github.com/wh0amitz/SharpADWS
        $guid_AA488748_3D0E_4A52_8747_AB42A7143760 = "AA488748-3D0E-4A52-8747-AB42A7143760" nocase

        // Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // https://github.com/bugch3ck/SharpEfsPotato
        $guid_AAB4D641_C310_4572_A9C2_6D12593AB28E = "AAB4D641-C310-4572-A9C2-6D12593AB28E" nocase

        // UAC bypass by abusing RPC and debug objects.
        // https://github.com/Kudaes/Elevator
        $guid_AAB75969_92BA_4632_9F78_AF52FA2BCE1E = "AAB75969-92BA-4632-9F78-AF52FA2BCE1E" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_AB2E1440_7EC2_45A2_8CF3_2975DE8A57AD = "AB2E1440-7EC2-45A2-8CF3-2975DE8A57AD" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_AB6CDF36_F336_4F14_8D69_3C190B7DEC65 = "AB6CDF36-F336-4F14-8D69-3C190B7DEC65" nocase

        // stealing Windows tokens
        // https://github.com/decoder-it/TokenStealer
        $guid_ABC32DBD_B697_482D_A763_7BA82FE9CEA2 = "ABC32DBD-B697-482D-A763-7BA82FE9CEA2" nocase

        // C++ stealer (passwords - cookies - forms - cards - wallets) 
        // https://github.com/SecUser1/Necro-Stealer
        $guid_ac3107cf_291c_449b_9121_55cd37f6383e = "ac3107cf-291c-449b-9121-55cd37f6383e" nocase

        // Get file less command execution for Lateral Movement.
        // https://github.com/juliourena/SharpNoPSExec
        $guid_acf7a8a9_3aaf_46c2_8aa8_2d12d7681baf = "acf7a8a9-3aaf-46c2-8aa8-2d12d7681baf" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_AD0067D9_4AF6_47C2_B0C3_D768A9624002 = "AD0067D9-4AF6-47C2-B0C3-D768A9624002" nocase

        // proof-of-concept of Process Forking.
        // https://github.com/D4stiny/ForkPlayground
        $guid_AD495F95_007A_4DC1_9481_0689CA0547D9 = "AD495F95-007A-4DC1-9481-0689CA0547D9" nocase

        // PEASS-ng - Privilege Escalation Awesome Scripts suite
        // https://github.com/peass-ng/PEASS-ng
        $guid_AD9F3A60_C492_4823_8F24_6F4854E7CBF5 = "AD9F3A60-C492-4823-8F24-6F4854E7CBF5" nocase

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_ADCEEFBA_CE43_4239_8AE8_7D8D43E66BB1 = "ADCEEFBA-CE43-4239-8AE8-7D8D43E66BB1" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_AE81B416_FBC4_4F88_9EFC_D07D8789355F = "AE81B416-FBC4-4F88-9EFC-D07D8789355F" nocase

        // Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // https://github.com/GhostPack/Seatbelt
        $guid_AEC32155_D589_4150_8FE7_2900DF4554C8 = "AEC32155-D589-4150-8FE7-2900DF4554C8" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_AEC32155_D589_4150_8FE7_2900DF4554C8 = "AEC32155-D589-4150-8FE7-2900DF4554C8" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_aef6547e_3822_4f96_9708_bcf008129b2b = "aef6547e-3822-4f96-9708-bcf008129b2b" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_AF0885E4_9E3B_49CA_9F13_0F869E8BF89D = "AF0885E4-9E3B-49CA-9F13-0F869E8BF89D" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_AF10B9C3_7969_4971_BD7A_5C50D8D2547F = "AF10B9C3-7969-4971-BD7A-5C50D8D2547F" nocase

        // Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // https://github.com/trustedsec/specula
        $guid_AF2D318C_2C5A_4C9D_BE4C_AA5B3E8037DB = "AF2D318C-2C5A-4C9D-BE4C-AA5B3E8037DB" nocase

        // A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // https://github.com/med0x2e/GadgetToJScript
        $guid_AF9C62A1_F8D2_4BE0_B019_0A7873E81EA9 = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_AFB848D0_68F8_42D1_A1C8_99DFBE034FCF = "AFB848D0-68F8-42D1-A1C8-99DFBE034FCF" nocase

        // similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // https://github.com/CICADA8-Research/RemoteKrbRelay
        $guid_B00DC126_D32B_429F_9BB5_97AF33BEE0E1 = "B00DC126-D32B-429F-9BB5-97AF33BEE0E1" nocase

        // RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // https://github.com/antonioCoco/RogueWinRM
        $guid_B03A3AF9_9448_43FE_8CEE_5A2C43BFAC86 = "B03A3AF9-9448-43FE-8CEE-5A2C43BFAC86" nocase

        // Bypassing EDR Solutions
        // https://github.com/helviojunior/hookchain
        $guid_B0C08C11_23C4_495F_B40B_14066F12FAAB = "B0C08C11-23C4-495F-B40B-14066F12FAAB" nocase

        // Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // https://x.com/0gtweet/status/1817859483445461406
        $guid_b10cfda1_f24f_441b_8f43_80cb93e786ec = "b10cfda1-f24f-441b-8f43-80cb93e786ec" nocase

        // open source ransomware - many variant in the wild
        // https://github.com/goliate/hidden-tear
        $guid_B138FFBA_1076_4B58_8A98_67B34E8A7C5C = "B138FFBA-1076-4B58-8A98-67B34E8A7C5C" nocase

        // binary padding to add junk data and change the on-disk representation of a file
        // https://github.com/mertdas/SharpIncrease
        $guid_B19E7FDE_C2CB_4C0A_9C5E_DFC73ADDB5C0 = "B19E7FDE-C2CB-4C0A-9C5E-DFC73ADDB5C0" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_B1CB9A30_FEA6_4467_BEC5_4803CCE9BF78 = "B1CB9A30-FEA6-4467-BEC5-4803CCE9BF78" nocase

        // EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // https://github.com/Mattiwatti/EfiGuard
        $guid_B2924789_9912_4B6F_8F7B_53240AC3BA0E = "B2924789-9912-4B6F-8F7B-53240AC3BA0E" nocase

        // Tunnel TCP connections through a file
        // https://github.com/fiddyschmitt/File-Tunnel
        $guid_B2B4238B_1055_4679_B7D5_7CCE2397098E = "B2B4238B-1055-4679-B7D5-7CCE2397098E" nocase

        // inspect token information
        // https://github.com/daem0nc0re/PrivFu
        $guid_B35266FB_81FD_4671_BF1D_CE6AEF8B8D64 = "B35266FB-81FD-4671-BF1D-CE6AEF8B8D64" nocase

        // Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // https://github.com/Idov31/Sandman
        $guid_B362EC25_70BD_4E6C_9744_173D20FDA392 = "B362EC25-70BD-4E6C-9744-173D20FDA392" nocase

        // An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // https://github.com/eladshamir/BadWindowsService
        $guid_B474B962_A46B_4D35_86F3_E8BA120C88C0 = "B474B962-A46B-4D35-86F3-E8BA120C88C0" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_B5205EBA_EC32_4C53_86A0_FAEEE7393EC0 = "B5205EBA-EC32-4C53-86A0-FAEEE7393EC0" nocase

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_B52E2D10_A94A_4605_914A_2DCEF6A757EF = "B52E2D10-A94A-4605-914A-2DCEF6A757EF" nocase

        // Abuses the Windows containers framework to bypass EDRs.
        // https://github.com/deepinstinct/ContainYourself
        $guid_B5627919_4DFB_49C6_AC1B_C757F4B4A103 = "B5627919-4DFB-49C6-AC1B-C757F4B4A103" nocase

        // Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // https://github.com/trustedsec/specula
        $guid_B58767EE_5185_4E99_818F_6285332400E6 = "B58767EE-5185-4E99-818F-6285332400E6" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_B59C7741_D522_4A41_BF4D_9BADDDEBB84A = "B59C7741-D522-4A41-BF4D-9BADDDEBB84A" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_B5C5BDD1_568E_44F6_91FF_B26962AF9A6C = "B5C5BDD1-568E-44F6-91FF-B26962AF9A6C" nocase

        // A native backdoor module for Microsoft IIS
        // https://github.com/0x09AL/IIS-Raid
        $guid_B5E39D15_9678_474A_9838_4C720243968B = "B5E39D15-9678-474A-9838-4C720243968B" nocase

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_B651A53C_FAE6_482E_A590_CA3B48B7F384 = "B651A53C-FAE6-482E-A590-CA3B48B7F384" nocase

        // Abusing Impersonation Privileges on Windows 10 and Server 2019
        // https://github.com/itm4n/PrintSpoofer
        $guid_B67143DE_321D_4034_AC1D_C6BB2D98563F = "B67143DE-321D-4034-AC1D-C6BB2D98563F" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_B672DE08_269D_4AA6_8535_D3BC59BB086B = "B672DE08-269D-4AA6-8535-D3BC59BB086B" nocase

        // Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // https://github.com/gitjdm/dumper2020
        $guid_B7355478_EEE0_46A7_807A_23CF0C5295AE = "B7355478-EEE0-46A7-807A-23CF0C5295AE" nocase

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_B7C64002_5002_410F_868C_826073AFA924 = "B7C64002-5002-410F-868C-826073AFA924" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_B7FF0EE8_6C68_46C6_AADB_58C0E3309FB2 = "B7FF0EE8-6C68-46C6-AADB-58C0E3309FB2" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_B84EFDD8_CEA0_4CCA_B7B8_3F8AB3A336B4 = "B84EFDD8-CEA0-4CCA-B7B8-3F8AB3A336B4" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_B87A5373_750C_44A7_BCEC_32185A3077AC = "B87A5373-750C-44A7-BCEC-32185A3077AC" nocase

        // Windows Privilege Escalation from User to Domain Admin.
        // https://github.com/antonioCoco/RemotePotato0
        $guid_B88B65D3_2689_4E39_892C_7532087174CB = "B88B65D3-2689-4E39-892C-7532087174CB" nocase

        // Patching signtool.exe to accept expired certificates for code-signing
        // https://github.com/hackerhouse-opensource/SignToolEx
        $guid_B8AEE3F1_0642_443C_B42C_33BADCD42365 = "B8AEE3F1-0642-443C-B42C-33BADCD42365" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_B8FF9629_B4CE_4871_A2CD_8E6D73F6DF9E = "B8FF9629-B4CE-4871-A2CD-8E6D73F6DF9E" nocase

        // Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // https://github.com/ricardojoserf/TrickDump
        $guid_B92B6B67_C7C8_4548_85EE_A215D74C000D = "B92B6B67-C7C8-4548-85EE-A215D74C000D" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_B9635D08_2BB2_404B_92B7_6A4981CB34F3 = "B9635D08-2BB2-404B-92B7-6A4981CB34F3" nocase

        // Cross-platform multi-protocol VPN software abused by attackers
        // https://github.com/SoftEtherVPN/SoftEtherVPN
        $guid_BA902FC8_E936_44AA_9C88_57D358BBB700 = "BA902FC8-E936-44AA-9C88-57D358BBB700" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_BA9D2748_1342_41A3_87F2_343E82D99813 = "BA9D2748-1342-41A3-87F2-343E82D99813" nocase

        // Stealthy Stand Alone PHP Web Shell
        // https://github.com/SpiderMate/Jatayu
        $guid_bb3b1a1f_0447_42a6_955a_88681fb88499 = "bb3b1a1f-0447-42a6-955a-88681fb88499" nocase

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_BB8A69C4_18B0_4FF2_989C_F70778FFBCE6 = "BB8A69C4-18B0-4FF2-989C-F70778FFBCE6" nocase

        // bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // https://github.com/undergroundwires/privacy.sexy
        $guid_bba575ec_0c7f_42e1_9b59_b7c9cca522ba = "bba575ec-0c7f-42e1-9b59-b7c9cca522ba" nocase

        // tool to authenticate to an LDAP/S server with a certificate through Schannel
        // https://github.com/AlmondOffSec/PassTheCert
        $guid_BBCD0202_C086_437C_A606_015456F90C46 = "BBCD0202-C086-437C-A606-015456F90C46" nocase

        // PrintNightmare exploitation
        // https://vx-underground.org/Archive/Dispossessor%20Leaks
        $guid_BBFBAF1D_A01E_4615_A208_786147320C20 = "BBFBAF1D-A01E-4615-A208-786147320C20" nocase

        // similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // https://github.com/CICADA8-Research/RemoteKrbRelay
        $guid_BC74B071_B36A_4EE8_8F03_5CF0A02C32DA = "BC74B071-B36A-4EE8-8F03-5CF0A02C32DA" nocase

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_BC9BC3C3_4FBC_4F36_866C_AC2B4758BEBE = "BC9BC3C3-4FBC-4F36-866C-AC2B4758BEBE" nocase

        // Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // https://github.com/Hackcraft-Labs/SharpShares
        $guid_BCBC884D_2D47_4138_B68F_7D425C9291F9 = "BCBC884D-2D47-4138-B68F-7D425C9291F9" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_BCE48DAE_232E_4B3D_B5B5_D0B29BB7E9DE = "BCE48DAE-232E-4B3D-B5B5-D0B29BB7E9DE" nocase

        // ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // https://github.com/GhostPack/ForgeCert
        $guid_bd346689_8ee6_40b3_858b_4ed94f08d40a = "bd346689-8ee6-40b3-858b-4ed94f08d40a" nocase

        // Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // https://github.com/TheD1rkMtr/D1rkInject
        $guid_BD602C80_47ED_4294_B981_0119D2200DB8 = "BD602C80-47ED-4294-B981-0119D2200DB8" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_BD628EE4_F3A0_4242_BCE3_95CA21114CD7 = "BD628EE4-F3A0-4242-BCE3-95CA21114CD7" nocase

        // RedPersist is a Windows Persistence tool written in C#
        // https://github.com/mertdas/RedPersist
        $guid_BD745A5E_A1E9_4FDD_A15B_E9F303A625AE = "BD745A5E-A1E9-4FDD-A15B-E9F303A625AE" nocase

        // RedPersist is a Windows Persistence tool written in C#
        // https://github.com/mertdas/RedPersist
        $guid_bd745a5e_a1e9_4fdd_a15b_e9f303a625ae = "bd745a5e-a1e9-4fdd-a15b-e9f303a625ae" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_BDED2735_F9E4_4B2E_9636_4EEDD78FC720 = "BDED2735-F9E4-4B2E-9636-4EEDD78FC720" nocase

        // Checks for the presence of known defensive products such as AV/EDR and logging tools
        // https://github.com/PwnDexter/SharpEDRChecker
        $guid_BDFEE233_3FED_42E5_AA64_492EB2AC7047 = "BDFEE233-3FED-42E5-AA64-492EB2AC7047" nocase

        // Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // https://github.com/mgeeky/ProtectMyTooling
        $guid_be642266_f34d_43c3_b6e4_eebf8e489519 = "be642266-f34d-43c3-b6e4-eebf8e489519" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_BE801141_0D4D_4950_85C8_8E93C9D3312F = "BE801141-0D4D-4950-85C8-8E93C9D3312F" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_BEB67A6E_4C54_4DE5_8C6B_2C12F44A7B92 = "BEB67A6E-4C54-4DE5-8C6B-2C12F44A7B92" nocase

        // Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // https://github.com/0x09AL/RdpThief
        $guid_BEBE6A01_0C03_4A7C_8FE9_9285F01C0B03 = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" nocase

        // Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // https://github.com/0x09AL/RdpThief
        $guid_BEBE6A01_0C03_4A7C_8FE9_9285F01C0B03 = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_BEE88186_769A_452C_9DD9_D0E0815D92BF = "BEE88186-769A-452C-9DD9-D0E0815D92BF" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_BF45108E_1E43_486B_A71D_5426BBB041DB = "BF45108E-1E43-486B-A71D-5426BBB041DB" nocase

        // bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // https://github.com/undergroundwires/privacy.sexy
        $guid_c06bb3f0_cbdc_4384_84cf_21b7fe6dfe01 = "c06bb3f0-cbdc-4384-84cf-21b7fe6dfe01" nocase

        // SingleDose is a framework to build shellcode load/process injection techniques
        // https://github.com/Wra7h/SingleDose
        $guid_C0E67E76_1C78_4152_9F79_FA27B4F7CCCA = "C0E67E76-1C78-4152-9F79-FA27B4F7CCCA" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_C10599E3_5A79_484F_940B_E4B61F256466 = "C10599E3-5A79-484F-940B-E4B61F256466" nocase

        // Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // https://github.com/cyberark/kubesploit
        $guid_c1090dbc_f2f7_4d90_a241_86e0c0217786 = "c1090dbc-f2f7-4d90-a241-86e0c0217786" nocase

        // SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // https://github.com/nccgroup/SCOMDecrypt
        $guid_C13C80ED_ED7A_4F27_93B1_DE6FD30A7B43 = "C13C80ED-ED7A-4F27-93B1-DE6FD30A7B43" nocase

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_C23B51C4_2475_4FC6_9B3A_27D0A2B99B0F = "C23B51C4-2475-4FC6-9B3A-27D0A2B99B0F" nocase

        // a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // https://github.com/zeze-zeze/NamedPipeMaster
        $guid_C2F24BBD_4807_49F5_B5E2_77FF0E8B756B = "C2F24BBD-4807-49F5-B5E2-77FF0E8B756B" nocase

        // The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // https://github.com/sevagas/macro_pack
        $guid_C33A0993_A331_406C_83F5_9357DF239B30 = "C33A0993-A331-406C-83F5-9357DF239B30" nocase

        // linikatz is a tool to attack AD on UNIX
        // https://github.com/CiscoCXSecurity/linikatz
        $guid_C34208EA_8C33_473D_A9B4_53FB40347EA0 = "C34208EA-8C33-473D-A9B4-53FB40347EA0" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_C346B912_51F2_4A2E_ACC3_0AC2D28920C6 = "C346B912-51F2-4A2E-ACC3-0AC2D28920C6" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_C373A937_312C_4C8D_BD04_BAAF568337E7 = "C373A937-312C-4C8D-BD04-BAAF568337E7" nocase

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_C37637FC_3792_4354_8F5B_7E319E4E5A6D = "C37637FC-3792-4354-8F5B-7E319E4E5A6D" nocase

        // Open-Source Remote Administration Tool For Windows C# (RAT)
        // https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $guid_C3C49F45_2589_4E04_9C50_71B6035C14AE = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_C3C49F45_2589_4E04_9C50_71B6035C14AE = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_C3C49F45_2589_4E04_9C50_71B6035C14AE = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase

        // Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // https://github.com/ricardojoserf/NativeBypassCredGuard
        $guid_c4d31433_5017_4b5e_956b_8a540520986c = "c4d31433-5017-4b5e-956b-8a540520986c" nocase

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_C526B877_6AFF_413C_BC03_1837FB63BC22 = "C526B877-6AFF-413C-BC03-1837FB63BC22" nocase

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_C5C6F4EA_7F09_4AC7_AC2A_1246302B9856 = "C5C6F4EA-7F09-4AC7-AC2A-1246302B9856" nocase

        // Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // https://github.com/ricardojoserf/TrickDump
        $guid_C666C98C_84C3_4A5A_A73B_2FC711CFCB7F = "C666C98C-84C3-4A5A-A73B-2FC711CFCB7F" nocase

        // Remote Command Executor: A OSS replacement for PsExec and RunAs
        // https://github.com/kavika13/RemCom
        $guid_C7038612_8183_67A7_8A9C_1379C2674156 = "C7038612-8183-67A7-8A9C-1379C2674156" nocase

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_c708b83f_4167_4b4c_a1db_d2011ecb3200 = "c708b83f-4167-4b4c-a1db-d2011ecb3200" nocase

        // ProxyLogon exploitation
        // https://github.com/hausec/ProxyLogon
        $guid_C715155F_2BE8_44E0_BD34_2960067874C8 = "C715155F-2BE8-44E0-BD34-2960067874C8" nocase

        // Another Windows Local Privilege Escalation from Service Account to System
        // https://github.com/antonioCoco/JuicyPotatoNG
        $guid_C73A4893_A5D1_44C8_900C_7B8850BBD2EC = "C73A4893-A5D1-44C8-900C-7B8850BBD2EC" nocase

        // Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // https://github.com/b4rtik/ATPMiniDump
        $guid_C7A0003B_98DC_4D57_8F09_5B90AAEFBDF4 = "C7A0003B-98DC-4D57-8F09-5B90AAEFBDF4" nocase

        // Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // https://github.com/outflanknl/Dumpert
        $guid_C7A0003B_98DC_4D57_8F09_5B90AAEFBDF4 = "C7A0003B-98DC-4D57-8F09-5B90AAEFBDF4" nocase

        // Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // https://github.com/quasar/Quasar
        $guid_C7C363BA_E5B6_4E18_9224_39BC8DA73172 = "C7C363BA-E5B6-4E18-9224-39BC8DA73172" nocase

        // extract and decrypt stored passwords from Google Chrome
        // https://github.com/BernKing/ChromeStealer
        $guid_c7c8b6fb_4e59_494e_aeeb_40cf342a7e88 = "c7c8b6fb-4e59-494e-aeeb-40cf342a7e88" nocase

        // A sleep obfuscation tool is used to encrypt the content of the .text section with RC4 (using SystemFunction032). To achieve this encryption a ROP chain is employed with QueueUserAPC and NtContinue.
        // https://github.com/RtlDallas/KrakenMask
        $guid_C7E4B529_6372_449A_9184_74E74E432FE8 = "C7E4B529-6372-449A-9184-74E74E432FE8" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_C7F1F871_8045_4414_9DC3_20F8AA42B4A1 = "C7F1F871-8045-4414-9DC3-20F8AA42B4A1" nocase

        // The OpenBullet web testing application.
        // https://github.com/openbullet/OpenBullet2
        $guid_C8482002_F594_4C28_9C46_960B036540A8 = "C8482002-F594-4C28-9C46-960B036540A8" nocase

        // TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // https://github.com/robertdavidgraham/masscan
        $guid_C88D7583_254F_4BE6_A9B9_89A5BB52E679 = "C88D7583-254F-4BE6-A9B9-89A5BB52E679" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_C8C12FA3_717F_4D35_B8B3_2E7F7A124E7C = "C8C12FA3-717F-4D35-B8B3-2E7F7A124E7C" nocase

        // ProxyLogon exploitation
        // https://github.com/hausec/ProxyLogon
        $guid_c8c9275b_4f46_4d48_9096_f0ec2e4ac8eb = "c8c9275b-4f46-4d48-9096-f0ec2e4ac8eb" nocase

        // PowerShell Constrained Language Mode Bypass
        // https://github.com/calebstewart/bypass-clm
        $guid_C8D738E6_8C30_4715_8AE5_6A8FBFE770A7 = "C8D738E6-8C30-4715-8AE5-6A8FBFE770A7" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_C91C8B29_82DF_49C0_986B_81182CF84E42 = "C91C8B29-82DF-49C0-986B-81182CF84E42" nocase

        // Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // https://github.com/Mayyhem/Maestro
        $guid_C9AF8FE1_CDFC_4DDD_B314_B44AD5EAD552 = "C9AF8FE1-CDFC-4DDD-B314-B44AD5EAD552" nocase

        // alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // https://github.com/OtterHacker/SetProcessInjection
        $guid_CA280845_1F10_4E65_9DE7_D9C6513BBD91 = "CA280845-1F10-4E65-9DE7-D9C6513BBD91" nocase

        // Find vulnerabilities in AD Group Policy
        // https://github.com/Group3r/Group3r
        $guid_CAA7AB97_F83B_432C_8F9C_C5F1530F59F7 = "CAA7AB97-F83B-432C-8F9C-C5F1530F59F7" nocase

        // Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // https://github.com/MrEmpy/Reaper
        $guid_CB561720_0175_49D9_A114_FE3489C53661 = "CB561720-0175-49D9-A114-FE3489C53661" nocase

        // Dump cookies directly from Chrome process memory
        // https://github.com/Meckazin/ChromeKatz
        $guid_CB790E12_603E_4C7C_9DC1_14A50819AF8C = "CB790E12-603E-4C7C-9DC1-14A50819AF8C" nocase

        // Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // https://github.com/moom825/Discord-RAT-2.0
        $guid_CC12258F_AF24_4773_A8E3_45D365BCBDE9 = "CC12258F-AF24-4773-A8E3-45D365BCBDE9" nocase

        // WinLicense key extraction via Intel PIN
        // https://github.com/charlesnathansmith/whatlicense
        $guid_CC127443_2519_4E04_8865_A6887658CDE5 = "CC127443-2519-4E04-8865-A6887658CDE5" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_CC848BD0_3B2D_4C1E_BFCF_75A9894A581D = "CC848BD0-3B2D-4C1E-BFCF-75A9894A581D" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_CD257C0A_9071_42B4_A2FF_180622DBCA96 = "CD257C0A-9071-42B4-A2FF-180622DBCA96" nocase

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_CD3578F6_01B7_48C9_9140_1AFA44B3A7C0 = "CD3578F6-01B7-48C9-9140-1AFA44B3A7C0" nocase

        // Indirect syscalls AV bypass
        // https://github.com/Cipher7/ChaiLdr
        $guid_cd4d53a9_2db8_4408_90a0_896b2bc4c9f8 = "cd4d53a9-2db8-4408-90a0-896b2bc4c9f8" nocase

        // Extracting NetNTLM without touching lsass.exe
        // https://github.com/MzHmO/NtlmThief
        $guid_CD517B47_6CA1_4AC3_BC37_D8A27F2F03A0 = "CD517B47-6CA1-4AC3-BC37-D8A27F2F03A0" nocase

        // A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // https://github.com/ihamburglar/fgdump
        $guid_CD8FD3D4_15FD_489C_A334_91F551B98022 = "CD8FD3D4-15FD-489C-A334-91F551B98022" nocase

        // COM ViewLogger - keylogger
        // https://github.com/CICADA8-Research/Spyndicapped
        $guid_cd9c66c8_8fcb_4d43_975b_a9c8d02ad090 = "cd9c66c8-8fcb-4d43-975b-a9c8d02ad090" nocase

        // A Silent (Hidden) Free Crypto Miner Builder
        // https://github.com/UnamSanctam/SilentCryptoMiner
        $guid_CE2307EB_A69E_0EB9_386C_D322223A10A9 = "CE2307EB-A69E-0EB9-386C-D322223A10A9" nocase

        // install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // https://github.com/trustedsec/The_Shelf
        $guid_CE23F388_34F5_4543_81D1_91CD244C9CB1 = "CE23F388-34F5-4543-81D1-91CD244C9CB1" nocase

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_CE5AD78C_DBDF_4D81_9A69_41B1DF683115 = "CE5AD78C-DBDF-4D81-9A69-41B1DF683115" nocase

        // .NET HttpClient proxy handler implementation for SOCKS proxies
        // https://github.com/bbepis/Nsocks
        $guid_CE5C7EF9_E890_48E5_8551_3E8F96DCB38F = "CE5C7EF9-E890-48E5-8551-3E8F96DCB38F" nocase

        // tool for inspecting system DLLs loaded into processes - looking for functions hooked from AV/EDR.
        // https://github.com/UmaRex01/HookSentry
        $guid_ce613fc8_3f97_4989_bc90_2027463ea37d = "ce613fc8-3f97-4989-bc90-2027463ea37d" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_CE61ADEE_C032_43EC_ACD8_E4A742F894A3 = "CE61ADEE-C032-43EC-ACD8-E4A742F894A3" nocase

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_CE62CBEE_DAA8_4E5E_AAAA_1F6FC291AB94 = "CE62CBEE-DAA8-4E5E-AAAA-1F6FC291AB94" nocase

        // Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // https://github.com/reveng007/SharpGmailC2
        $guid_CE895D82_85AA_41D9_935A_9625312D87D0 = "CE895D82-85AA-41D9-935A-9625312D87D0" nocase

        // Creating a persistent service
        // https://github.com/uknowsec/CreateService
        $guid_cf25b9f3_849e_447f_a029_2fef5969eca3 = "cf25b9f3-849e-447f-a029-2fef5969eca3" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_CF8C386C_46B2_4F40_BCB1_774C01E72B1C = "CF8C386C-46B2-4F40-BCB1-774C01E72B1C" nocase

        // decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // https://github.com/mez-0/DecryptRDCManager
        $guid_CF924967_0AEC_43B2_B891_D67B6DB9F523 = "CF924967-0AEC-43B2-B891-D67B6DB9F523" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_CFE81801_C2C5_4444_BE67_64EFFEFDCD73 = "CFE81801-C2C5-4444-BE67-64EFFEFDCD73" nocase

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_D00C849B_4FA5_4E84_B9EF_B1C8C338647A = "D00C849B-4FA5-4E84-B9EF-B1C8C338647A" nocase

        // Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // https://github.com/danielbohannon/Invoke-Obfuscation
        $guid_d0a9150d_b6a4_4b17_a325_e3a24fed0aa9 = "d0a9150d-b6a4-4b17-a325-e3a24fed0aa9" nocase

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_D0CBA7AF_93F5_378A_BB11_2A5D9AA9C4D7 = "D0CBA7AF-93F5-378A-BB11-2A5D9AA9C4D7" nocase

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_D0CBA7AF_93F5_378A_BB11_2A5D9AA9C4D7 = "D0CBA7AF-93F5-378A-BB11-2A5D9AA9C4D7" nocase

        // C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // https://github.com/rvrsh3ll/SharpEdge
        $guid_D116BEC7_8DEF_4FCE_BF84_C8504EF4E481 = "D116BEC7-8DEF-4FCE-BF84-C8504EF4E481" nocase

        // A quick scanner for the CVE-2019-0708 "BlueKeep" vulnerability
        // https://github.com/robertdavidgraham/rdpscan
        $guid_D116CC32_BC4F_4FAD_B09C_0D6459D1C1B6 = "D116CC32-BC4F-4FAD-B09C-0D6459D1C1B6" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_D19BD978_267A_4BF0_85CC_851E280FF4C2 = "D19BD978-267A-4BF0-85CC-851E280FF4C2" nocase

        // ADCollector is a lightweight tool that enumerates the Active Directory environment
        // https://github.com/dev-2null/ADCollector
        $guid_D1AE1ACF_8AA2_4935_ACDF_EC22BAE2DF76 = "D1AE1ACF-8AA2-4935-ACDF-EC22BAE2DF76" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_D1CCDA5D_E460_4ACC_B51A_730DE8F0ECF3 = "D1CCDA5D-E460-4ACC-B51A-730DE8F0ECF3" nocase

        // indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // https://github.com/CaptainNox/Hypnos
        $guid_D210570B_F1A0_4B66_9301_F7A54978C178 = "D210570B-F1A0-4B66-9301-F7A54978C178" nocase

        // audit the security of read-only domain controllers
        // https://github.com/wh0amitz/SharpRODC
        $guid_D305F8A3_019A_4CDF_909C_069D5B483613 = "D305F8A3-019A-4CDF-909C-069D5B483613" nocase

        // PrintNightmare exploitation
        // https://github.com/outflanknl/PrintNightmare
        $guid_D30C9D6B_1F45_47BD_825B_389FE8CC9069 = "D30C9D6B-1F45-47BD-825B-389FE8CC9069" nocase

        // AD recon tool based on ADSI and reflective DLL
        // https://github.com/outflanknl/Recon-AD
        $guid_D30C9D6B_1F45_47BD_825B_389FE8CC9069 = "D30C9D6B-1F45-47BD-825B-389FE8CC9069" nocase

        // Fake Windows logon screen to steal passwords
        // https://github.com/bitsadmin/fakelogonscreen
        $guid_D35A55BD_3189_498B_B72F_DC798172E505 = "D35A55BD-3189-498B-B72F-DC798172E505" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_D3E7005E_6C5B_47F3_A0B3_028C81C0C1ED = "D3E7005E-6C5B-47F3-A0B3-028C81C0C1ED" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_D47C706B_152F_46B5_840A_4EBB2CFAFE33 = "D47C706B-152F-46B5-840A-4EBB2CFAFE33" nocase

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_d494a4bc_3867_436a_93ef_737f9e0522eb = "d494a4bc-3867-436a-93ef-737f9e0522eb" nocase

        // Process injection technique
        // https://github.com/CICADA8-Research/IHxExec
        $guid_d5092358_f3ab_4712_9c7f_d9ec4390193c = "d5092358-f3ab-4712-9c7f-d9ec4390193c" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_D52AB3F8_15D3_49C5_9EAC_468CDF65FB22 = "D52AB3F8-15D3-49C5-9EAC-468CDF65FB22" nocase

        // Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // https://github.com/BC-SECURITY/Empire
        $guid_D5865774_CD82_4CCE_A3F1_7F2C4639301B = "D5865774-CD82-4CCE-A3F1-7F2C4639301B" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_D5C4F5A2_5713_4A0A_A833_F9466AE5A339 = "D5C4F5A2-5713-4A0A-A833-F9466AE5A339" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_D640C36B_2C66_449B_A145_EB98322A67C8 = "D640C36B-2C66-449B-A145-EB98322A67C8" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_D64E40BB_9DAC_4491_8406_2CA2F2853F76 = "D64E40BB-9DAC-4491-8406-2CA2F2853F76" nocase

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_D6948EFC_AA15_413D_8EF1_032C149D3FBB = "D6948EFC-AA15-413D-8EF1-032C149D3FBB" nocase

        // Enumerate and decrypt TeamViewer credentials from Windows registry
        // https://github.com/V1V1/DecryptTeamViewer
        $guid_D6AAED62_BBFC_4F2A_A2A4_35EC5B2A4E07 = "D6AAED62-BBFC-4F2A-A2A4-35EC5B2A4E07" nocase

        // EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // https://github.com/Mattiwatti/EfiGuard
        $guid_D7484EBA_6357_4D81_B355_066E28D5DF72 = "D7484EBA-6357-4D81-B355-066E28D5DF72" nocase

        // PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // https://github.com/topotam/PetitPotam
        $guid_D78924E1_7F2B_4315_A2D2_24124C7828F8 = "D78924E1-7F2B-4315-A2D2-24124C7828F8" nocase

        // HTTP/S Beaconing Implant
        // https://github.com/silentbreaksec/Throwback
        $guid_D7D20588_8C18_4796_B2A4_386AECF14256 = "D7D20588-8C18-4796-B2A4-386AECF14256" nocase

        // Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // https://github.com/gitjdm/dumper2020
        $guid_D8091ED0_5E78_4AF5_93EE_A5AA6E978430 = "D8091ED0-5E78-4AF5-93EE-A5AA6E978430" nocase

        // erase specified records from Windows event logs
        // https://github.com/QAX-A-Team/EventCleaner
        $guid_D8A76296_A666_46C7_9CA0_254BA97E3B7C = "D8A76296-A666-46C7-9CA0-254BA97E3B7C" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_D8B2F4F4_2B59_4457_B710_F15844570997 = "D8B2F4F4-2B59-4457-B710-F15844570997" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_D8BDABF6_6A96_4B48_8C1C_B6E78CBBF50E = "D8BDABF6-6A96-4B48-8C1C-B6E78CBBF50E" nocase

        // Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // https://github.com/ricardojoserf/TrickDump
        $guid_D8FC3807_CEAA_4F6A_9C8F_CC96F99D1F04 = "D8FC3807-CEAA-4F6A-9C8F-CC96F99D1F04" nocase

        // C# AV/EDR Killer using less-known driver (BYOVD)
        // https://github.com/ph4nt0mbyt3/Darkside
        $guid_D90EFC93_2F8B_4427_B967_0E78ED45611E = "D90EFC93-2F8B-4427-B967-0E78ED45611E" nocase

        // PEASS - Privilege Escalation Awesome Scripts SUITE
        // https://github.com/carlospolop/PEASS-ng
        $guid_D934058E_A7DB_493F_A741_AE8E3DF867F4 = "D934058E-A7DB-493F-A741-AE8E3DF867F4" nocase

        // PEASS-ng - Privilege Escalation Awesome Scripts suite
        // https://github.com/peass-ng/PEASS-ng
        $guid_D934058E_A7DB_493F_A741_AE8E3DF867F4 = "D934058E-A7DB-493F-A741-AE8E3DF867F4" nocase

        // meterpreter stager
        // https://github.com/SherifEldeeb/TinyMet
        $guid_DA06A931_7DCA_4149_853D_641B8FAA1AB9 = "DA06A931-7DCA-4149-853D-641B8FAA1AB9" nocase

        // PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // https://github.com/GDSSecurity/PSAttack
        $guid_DA1B7904_0DDC_45A0_875F_33BBA2236C44 = "DA1B7904-0DDC-45A0-875F-33BBA2236C44" nocase

        // unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $guid_DA230B64_14EA_4D49_96E1_FA5EFED9010B = "DA230B64-14EA-4D49-96E1-FA5EFED9010B" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_DA7DF89C_447D_4C2D_9C75_933037BF245E = "DA7DF89C-447D-4C2D-9C75-933037BF245E" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_DAE3997B_D51B_4D9F_9F11_2EBC6FDDF57C = "DAE3997B-D51B-4D9F-9F11-2EBC6FDDF57C" nocase

        // .Net Assembly to block ETW telemetry in current process
        // https://github.com/Soledge/BlockEtw
        $guid_DAEDF7B3_8262_4892_ADC4_425DD5F85BCA = "DAEDF7B3-8262-4892-ADC4-425DD5F85BCA" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_DAFE686A_461B_402B_BBD7_2A2F4C87C773 = "DAFE686A-461B-402B-BBD7-2A2F4C87C773" nocase

        // MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // https://github.com/MaLDAPtive/Invoke-Maldaptive
        $guid_db015ab1_abcd_1234_5678_133337c0ffee = "db015ab1-abcd-1234-5678-133337c0ffee" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_DB234158_233E_4EC4_A2CE_EF02699563A2 = "DB234158-233E-4EC4-A2CE-EF02699563A2" nocase

        // Adaptive DLL hijacking / dynamic export forwarding
        // https://github.com/monoxgas/Koppeling
        $guid_DB8A345D_E19C_4C2A_9FDF_16BF4DD03717 = "DB8A345D-E19C-4C2A-9FDF-16BF4DD03717" nocase

        // Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // https://github.com/moom825/Discord-RAT-2.0
        $guid_DBAE6A6E_AE23_4DE9_9AB2_6A8D2CD59DEF = "DBAE6A6E-AE23-4DE9-9AB2-6A8D2CD59DEF" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_DC199D9E_CF10_41DD_BBCD_98E71BA8679D = "DC199D9E-CF10-41DD-BBCD-98E71BA8679D" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_DC199D9E_CF10_41DD_BBCD_98E71BA8679D = "DC199D9E-CF10-41DD-BBCD-98E71BA8679D" nocase

        // The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // https://github.com/hackerschoice/gsocket
        $guid_dc3c1af9_ea3d_4401_9158_eb6dda735276 = "dc3c1af9-ea3d-4401-9158-eb6dda735276" nocase

        // C++ stealer (passwords - cookies - forms - cards - wallets) 
        // https://github.com/SecUser1/PredatorTheStealer
        $guid_DC3E0E14_6342_41C9_BECC_3653BF533CCC = "DC3E0E14-6342-41C9-BECC-3653BF533CCC" nocase

        // The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // https://github.com/am0nsec/HellsGate
        $guid_DC6187CB_D5DF_4973_84A2_F92AAE90CDA9 = "DC6187CB-D5DF-4973-84A2-F92AAE90CDA9" nocase

        // TartarusGate Bypassing EDRs
        // https://github.com/trickster0/TartarusGate
        $guid_DC6187CB_D5DF_4973_84A2_F92AAE90CDA9 = "DC6187CB-D5DF-4973-84A2-F92AAE90CDA9" nocase

        // SMBScan is a tool to enumerate file shares on an internal network.
        // https://github.com/jeffhacks/smbscan
        $guid_dc9978d7_6299_4c5a_a22d_a039cdc716ea = "dc9978d7-6299-4c5a-a22d-a039cdc716ea" nocase

        // Command and Control Framework written in C#
        // https://github.com/rasta-mouse/SharpC2
        $guid_DE7B9E6B_F73B_4573_A4C7_D314B528CFCB = "DE7B9E6B-F73B-4573-A4C7-D314B528CFCB" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_DEED6795_9EC9_4B2C_95E0_9E465DA61755 = "DEED6795-9EC9-4B2C-95E0-9E465DA61755" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_DFE11C77_62FA_4011_8398_38626C02E382 = "DFE11C77-62FA-4011-8398-38626C02E382" nocase

        // Dump various types of Windows credentials without injecting in any process
        // https://github.com/quarkslab/quarkspwdump
        $guid_E0362605_CC11_4CD5_AFF7_B50934438658 = "E0362605-CC11-4CD5-AFF7-B50934438658" nocase

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_E049487C_C5BD_471E_99AE_C756E70B6520 = "E049487C-C5BD-471E-99AE-C756E70B6520" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_E08BAA9C_9D20_4C9A_8933_EC567F39F54C = "E08BAA9C-9D20-4C9A-8933-EC567F39F54C" nocase

        // Patching AmsiOpenSession by forcing an error branching
        // https://github.com/TheD1rkMtr/AMSI_patch
        $guid_E09F4899_D8B3_4282_9E3A_B20EE9A3D463 = "E09F4899-D8B3-4282-9E3A-B20EE9A3D463" nocase

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_e11cbe43_b8bc_4042_a4a5_c8e960925c83 = "e11cbe43-b8bc-4042-a4a5-c8e960925c83" nocase

        // PoC Implementation of a fully dynamic call stack spoofer
        // https://github.com/klezVirus/SilentMoonwalk
        $guid_E11DC25D_E96D_495D_8968_1BA09C95B673 = "E11DC25D-E96D-495D-8968-1BA09C95B673" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_E17B7339_C788_4DBE_B382_3AEDB024073D = "E17B7339-C788-4DBE-B382-3AEDB024073D" nocase

        // disable TamperProtection and other Defender / MDE components
        // https://github.com/AlteredSecurity/Disable-TamperProtection
        $guid_E192C3DF_AE34_4E32_96BA_3D6B56EA76A4 = "E192C3DF-AE34-4E32-96BA-3D6B56EA76A4" nocase

        // ScriptSentry finds misconfigured and dangerous logon scripts.
        // https://github.com/techspence/ScriptSentry
        $guid_e1cd2b55_3b4f_41bd_a168_40db41e34349 = "e1cd2b55-3b4f-41bd-a168-40db41e34349" nocase

        // A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // https://github.com/ihamburglar/fgdump
        $guid_E1D50AB4_E1CD_4C31_AED5_E957D2E6B01F = "E1D50AB4-E1CD-4C31-AED5-E957D2E6B01F" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_E211C5CD_85F0_48D2_A18F_2E59AD47DDC3 = "E211C5CD-85F0-48D2-A18F-2E59AD47DDC3" nocase

        // Lifetime AMSI bypass
        // https://github.com/ZeroMemoryEx/Amsi-Killer
        $guid_E2E64E89_8ACE_4AA1_9340_8E987F5F142F = "E2E64E89-8ACE-4AA1-9340-8E987F5F142F" nocase

        // .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // https://github.com/G0ldenGunSec/SharpSecDump
        $guid_E2FDD6CC_9886_456C_9021_EE2C47CF67B7 = "E2FDD6CC-9886-456C-9021-EE2C47CF67B7" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_E3104B33_DB3D_4C83_B393_1E05E1FF2B10 = "E3104B33-DB3D-4C83-B393-1E05E1FF2B10" nocase

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_E377F156_BAED_4086_B534_3CC43164607A = "E377F156-BAED-4086-B534-3CC43164607A" nocase

        // Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // https://github.com/ricardojoserf/NativeBypassCredGuard
        $guid_E383DFEA_EC22_4667_9434_3F2591A03740 = "E383DFEA-EC22-4667-9434-3F2591A03740" nocase

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_E3AEA3F6_D548_4989_9A42_80BAC9321AE0 = "E3AEA3F6-D548-4989-9A42-80BAC9321AE0" nocase

        // C# implementation of harmj0y's PowerView
        // https://github.com/tevora-threat/SharpView/
        $guid_e42e5cf9_be25_4011_9623_8565b193a506 = "e42e5cf9-be25-4011-9623-8565b193a506" nocase

        // SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // https://github.com/Mayyhem/SharpSCCM/
        $guid_E4D9EF39_0FCE_4573_978B_ABF8DF6AEC23 = "E4D9EF39-0FCE-4573-978B-ABF8DF6AEC23" nocase

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_E51B9AEB_5F48_4C5C_837E_3A2743917427 = "E51B9AEB-5F48-4C5C-837E-3A2743917427" nocase

        // PSAmsi is a tool for auditing and defeating AMSI signatures.
        // https://github.com/cobbr/PSAmsi
        $guid_e53f158d_8aa2_8c53_da89_ab75d32c8c01 = "e53f158d-8aa2-8c53-da89-ab75d32c8c01" nocase

        // Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // https://github.com/YOLOP0wn/POSTDump
        $guid_E54195F0_060C_4B24_98F2_AD9FB5351045 = "E54195F0-060C-4B24-98F2-AD9FB5351045" nocase

        // perform minidump of LSASS process using few technics to avoid detection
        // https://github.com/YOLOP0wn/POSTDump
        $guid_E54195F0_060C_4B24_98F2_AD9FB5351045 = "E54195F0-060C-4B24-98F2-AD9FB5351045" nocase

        // perform minidump of LSASS process using few technics to avoid detection.
        // https://github.com/YOLOP0wn/POSTDump
        $guid_E54195F0_060C_4B24_98F2_AD9FB5351045 = "E54195F0-060C-4B24-98F2-AD9FB5351045" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_E55F7214_8CC4_4E1D_AEDB_C908D23902A4 = "E55F7214-8CC4-4E1D-AEDB-C908D23902A4" nocase

        // Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // https://github.com/LimerBoy/Adamantium-Thief
        $guid_E6104BC9_FEA9_4EE9_B919_28156C1F2EDE = "E6104BC9-FEA9-4EE9-B919-28156C1F2EDE" nocase

        // create hidden scheduled tasks
        // https://github.com/0x727/SchTask_0x727
        $guid_E61C950E_A03D_40E2_AAD5_304C48570364 = "E61C950E-A03D-40E2-AAD5-304C48570364" nocase

        // A tool to find folders excluded from AV real-time scanning using a time oracle
        // https://github.com/bananabr/TimeException
        $guid_e69f0324_3afb_485e_92c7_cb097ea47caf = "e69f0324-3afb-485e-92c7-cb097ea47caf" nocase

        // AoratosWin A tool that removes traces of executed applications on Windows OS
        // https://github.com/PinoyWH1Z/AoratosWin
        $guid_E731C71B_4D1B_4BE7_AA4D_EDA52AF7F256 = "E731C71B-4D1B-4BE7-AA4D-EDA52AF7F256" nocase

        // Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // https://github.com/moom825/Discord-RAT-2.0
        $guid_E776B801_614D_4E3C_A446_5A35B0CF3D08 = "E776B801-614D-4E3C-A446-5A35B0CF3D08" nocase

        // a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // https://github.com/zeze-zeze/NamedPipeMaster
        $guid_E7BFFEE1_07C1_452C_8AF8_6AD30B1844FF = "E7BFFEE1-07C1-452C-8AF8-6AD30B1844FF" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_E7F99164_F00F_4B2A_86A9_8EB5F659F34C = "E7F99164-F00F-4B2A-86A9-8EB5F659F34C" nocase

        // Command line interface to dump LSASS memory to disk via SilentProcessExit
        // https://github.com/deepinstinct/LsassSilentProcessExit
        $guid_E82BCAD1_0D2B_4E95_B382_933CF78A8128 = "E82BCAD1-0D2B-4E95-B382-933CF78A8128" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_E832E9B8_2158_4FC0_89A1_56C6ECC10F6B = "E832E9B8-2158-4FC0-89A1-56C6ECC10F6B" nocase

        // Decrypt GlobalProtect configuration and cookie files.
        // https://github.com/rotarydrone/GlobalUnProtect
        $guid_E9172085_1595_4E98_ABF8_E890D2489BB5 = "E9172085-1595-4E98-ABF8-E890D2489BB5" nocase

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_E991E6A7_31EA_42E3_A471_90F0090E3AFD = "E991E6A7-31EA-42E3-A471-90F0090E3AFD" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_E9D90B2A_F563_4A5E_9EFB_B1D6B1E7F8CB = "E9D90B2A-F563-4A5E-9EFB-B1D6B1E7F8CB" nocase

        // Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // https://github.com/Idov31/Sandman
        $guid_E9F7C24C_879D_49F2_B9BF_2477DC28E2EE = "E9F7C24C-879D-49F2-B9BF-2477DC28E2EE" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_EA1FB2D4_B5A7_47A6_B097_2F4D29E23010 = "EA1FB2D4-B5A7-47A6-B097-2F4D29E23010" nocase

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_EA92F1E6_3F34_48F8_8B0A_F2BBC19220EF = "EA92F1E6-3F34-48F8-8B0A-F2BBC19220EF" nocase

        // Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // https://github.com/ly4k/SpoolFool
        $guid_EC49A1B1_4DAA_47B1_90D1_787D44C641C0 = "EC49A1B1-4DAA-47B1-90D1-787D44C641C0" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_EC62CE1D_ADD7_419A_84A9_D6A04E866197 = "EC62CE1D-ADD7-419A-84A9-D6A04E866197" nocase

        // acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // https://github.com/decoder-it/KrbRelay-SMBServer
        $guid_ED839154_90D8_49DB_8CDD_972D1A6B2CFD = "ED839154-90D8-49DB-8CDD-972D1A6B2CFD" nocase

        // a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings).
        // https://github.com/Dec0ne/KrbRelayUp
        $guid_ED83E265_D48E_4B0D_8C22_D9D0A67C78F2 = "ED83E265-D48E-4B0D-8C22-D9D0A67C78F2" nocase

        // leverages the Process Forking technique using the RtlCreateProcessReflection API to clone the lsass.exe process. Once the clone is created - it utilizes MINIDUMP_CALLBACK_INFORMATION callbacks to generate a memory dump of the cloned process
        // https://github.com/Offensive-Panda/LsassReflectDumping
        $guid_edd9d1b4_27f7_424a_aa21_794b19231741 = "edd9d1b4-27f7-424a-aa21-794b19231741" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_EE03FAA9_C9E8_4766_BD4E_5CD54C7F13D3 = "EE03FAA9-C9E8-4766-BD4E-5CD54C7F13D3" nocase

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_EE64B207_D973_489B_84A8_B718B93E039B = "EE64B207-D973-489B-84A8-B718B93E039B" nocase

        // disable windows defender. (through the WSC api)
        // https://github.com/es3n1n/no-defender
        $guid_EE666120_EE4C_4D91_A545_66BEAA1830C1 = "EE666120-EE4C-4D91-A545-66BEAA1830C1" nocase

        // Decrypt Veeam database passwords
        // https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $guid_EE728741_4BD4_4F7C_8E41_B8328706EA84 = "EE728741-4BD4-4F7C-8E41-B8328706EA84" nocase

        // Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // https://github.com/TheD1rkMtr/D1rkInject
        $guid_EEC35BCF_E990_4260_828D_2B4F9AC97269 = "EEC35BCF-E990-4260-828D-2B4F9AC97269" nocase

        // Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // https://github.com/senzee1984/InflativeLoading
        $guid_EEC48565_5B42_491A_8BBB_16AC0C40C367 = "EEC48565-5B42-491A-8BBB-16AC0C40C367" nocase

        // TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // https://github.com/Flangvik/TeamFiltration
        $guid_EF143476_E53D_4C39_8DBB_A6AC7883236C = "EF143476-E53D-4C39-8DBB-A6AC7883236C" nocase

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_EFFE3048_E904_48FD_B8C0_290E8E9290FB = "EFFE3048-E904-48FD-B8C0-290E8E9290FB" nocase

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_F0005D08_6278_4BFE_B492_F86CCEC797D5 = "F0005D08-6278-4BFE-B492-F86CCEC797D5" nocase

        // Dump the memory of any PPL with a Userland exploit chain
        // https://github.com/itm4n/PPLmedic
        $guid_F00A3B5F_D9A9_4582_BBCE_FD10EFBF0C17 = "F00A3B5F-D9A9-4582-BBCE-FD10EFBF0C17" nocase

        // Performing Indirect Clean Syscalls
        // https://github.com/Maldev-Academy/HellHall
        $guid_F06EAC7B_6996_4E78_B045_0DF6ED201367 = "F06EAC7B-6996-4E78-B045-0DF6ED201367" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_F0A581F1_D9BE_42EB_B262_E6A7CC839D2B = "F0A581F1-D9BE-42EB-B262-E6A7CC839D2B" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_F142A341_5EE0_442D_A15F_98AE9B48DBAE = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_F142A341_5EE0_442D_A15F_98AE9B48DBAE = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_F142A341_5EE0_442D_A15F_98AE9B48DBAE = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_F142A341_5EE0_442D_A15F_98AE9B48DBAE = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_F142A341_5EE0_442D_A15F_98AE9B48DBAE = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" nocase

        // Credential Guard Bypass Via Patching Wdigest Memory
        // https://github.com/wh0amitz/BypassCredGuard
        $guid_F1527C49_CA1F_4994_BB9D_E20DD2C607FD = "F1527C49-CA1F-4994-BB9D-E20DD2C607FD" nocase

        // This is a tool for grabbing browser passwords
        // https://github.com/QAX-A-Team/BrowserGhost
        $guid_F1653F20_D47D_4F29_8C55_3C835542AF5F = "F1653F20-D47D-4F29-8C55-3C835542AF5F" nocase

        // .NET 4.0 CLR Project to retrieve Chromium data such as cookies - history and saved logins.
        // https://github.com/djhohnstein/SharpChromium
        $guid_F1653F20_D47D_4F29_8C55_3C835542AF5F = "F1653F20-D47D-4F29-8C55-3C835542AF5F" nocase

        // Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // https://github.com/0xthirteen/SharpRDP
        $guid_F1DF1D0F_FF86_4106_97A8_F95AAF525C54 = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" nocase

        // Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $guid_F1E836C1_2279_49B3_84CC_ED8B048FCC44 = "F1E836C1-2279-49B3-84CC-ED8B048FCC44" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_F233D36D_B64A_4F14_A9F9_B8557C2D4F5D = "F233D36D-B64A-4F14-A9F9-B8557C2D4F5D" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_F2378C48_D441_49E7_B094_1E8642A7E7C0 = "F2378C48-D441-49E7-B094-1E8642A7E7C0" nocase

        // credential access tool used by the Dispossessor ransomware group
        // https://github.com/n37sn4k3/BrowserDataGrabber
        $guid_f2691b74_129f_4ac2_a88a_db4b0f36b609 = "f2691b74-129f-4ac2-a88a-db4b0f36b609" nocase

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_F2EC73D1_D533_4EE4_955A_A62E306472CC = "F2EC73D1-D533-4EE4-955A-A62E306472CC" nocase

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A35 = "F3037587-1A3B-41F1-AA71-B026EFDB2A35" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A35 = "F3037587-1A3B-41F1-AA71-B026EFDB2A35" nocase

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A40 = "F3037587-1A3B-41F1-AA71-B026EFDB2A40" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A40 = "F3037587-1A3B-41F1-AA71-B026EFDB2A40" nocase

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A45 = "F3037587-1A3B-41F1-AA71-B026EFDB2A45" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A45 = "F3037587-1A3B-41F1-AA71-B026EFDB2A45" nocase

        // Github as C2
        // https://github.com/TheD1rkMtr/GithubC2
        $guid_F3C62326_E221_4481_AC57_EF7F76AAF27B = "F3C62326-E221-4481-AC57-EF7F76AAF27B" nocase

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_F3FEBDE7_FBC8_48EC_8F24_5F33B8ACFB2A = "F3FEBDE7-FBC8-48EC-8F24-5F33B8ACFB2A" nocase

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_F56E4E1A_AB7A_4494_ACB9_8757164B0524 = "F56E4E1A-AB7A-4494-ACB9-8757164B0524" nocase

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_F5A53B43_5D6D_48EC_BC44_C0C1A0CEFA8D = "F5A53B43-5D6D-48EC-BC44-C0C1A0CEFA8D" nocase

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_F5BFA34B_3CDE_4C77_9162_96666303FDEA = "F5BFA34B-3CDE-4C77-9162-96666303FDEA" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_F602DAFE_E8A2_4CB2_AF0E_656CD357D821 = "F602DAFE-E8A2-4CB2-AF0E-656CD357D821" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_F60C3246_D449_412B_A858_3B5E84494D1A = "F60C3246-D449-412B-A858-3B5E84494D1A" nocase

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_F60CD6D5_4B1C_4293_829E_9C10D21AE8A3 = "F60CD6D5-4B1C-4293-829E-9C10D21AE8A3" nocase

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_F61EEB46_5352_4349_B880_E4A0B38EC0DB = "F61EEB46-5352-4349-B880-E4A0B38EC0DB" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_F70D2B71_4AAE_4B24_9DAE_55BC819C78BB = "F70D2B71-4AAE-4B24-9DAE-55BC819C78BB" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_F7581FB4_FAF5_4CD0_888A_B588F5BC69CD = "F7581FB4-FAF5-4CD0-888A-B588F5BC69CD" nocase

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_F7FA0241_1143_475B_A49A_AF44FA2F1339 = "F7FA0241-1143-475B-A49A-AF44FA2F1339" nocase

        // CVE-2024-6768: Improper validation of specified quantity in input produces an unrecoverable state in CLFS.sys causing a BSoD
        // https://github.com/fortra/CVE-2024-6768
        $guid_F8285C79_AAC0_4FAD_B1DA_15CB4514B1D8 = "F8285C79-AAC0-4FAD-B1DA-15CB4514B1D8" nocase

        // similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // https://github.com/CICADA8-Research/RemoteKrbRelay
        $guid_F8317556_F82B_4FE2_9857_3E8DE896AA32 = "F8317556-F82B-4FE2-9857-3E8DE896AA32" nocase

        // Google Chrome Passwords , Cookies and SystemInfo Dumper
        // https://github.com/xelroth/ShadowStealer
        $guid_F835A9E7_2542_45C2_9D85_EC0C9FDFFB16 = "F835A9E7-2542-45C2-9D85-EC0C9FDFFB16" nocase

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_F90C57DF_CDE4_4CDE_A2B9_9124C307D53A = "F90C57DF-CDE4-4CDE-A2B9-9124C307D53A" nocase

        // An obfuscation tool for .Net + Native files
        // https://github.com/NYAN-x-CAT/Lime-Crypter
        $guid_F93C99ED_28C9_48C5_BB90_DD98F18285A6 = "F93C99ED-28C9-48C5-BB90-DD98F18285A6" nocase

        // Abuses the Windows containers framework to bypass EDRs.
        // https://github.com/deepinstinct/ContainYourself
        $guid_FA0DAF13_5058_4382_AE07_65E44AFB5592 = "FA0DAF13-5058-4382-AE07-65E44AFB5592" nocase

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_FA2052FB_9E23_43C8_A0EF_43BBB710DC61 = "FA2052FB-9E23-43C8-A0EF-43BBB710DC61" nocase

        // Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // https://github.com/moom825/Discord-RAT-2.0
        $guid_FAA8C7E2_4409_44F5_B2CA_EBBA4D4F41F0 = "FAA8C7E2-4409-44F5-B2CA-EBBA4D4F41F0" nocase

        // Manage everything in one place
        // https://github.com/fleetdm/fleet
        $guid_FAECC814_3F3F_4CA0_8C2B_72D5E4670B92 = "FAECC814-3F3F-4CA0-8C2B-72D5E4670B92" nocase

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_FAFE5A3C_05BC_4B6F_8BA4_2B95027CBFEA = "FAFE5A3C-05BC-4B6F-8BA4-2B95027CBFEA" nocase

        // Fuzzer for Windows kernel syscalls.
        // https://github.com/waleedassar/SimpleNTSyscallFuzzer
        $guid_FB351327_0816_448B_8FB7_63B550D6C808 = "FB351327-0816-448B-8FB7-63B550D6C808" nocase

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_FB9B5E61_7C34_4280_A211_E979E1D6977F = "FB9B5E61-7C34-4280-A211-E979E1D6977F" nocase

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_FC5A1C5A_65B4_452A_AA4E_E6DCF1FA04FB = "FC5A1C5A-65B4-452A-AA4E-E6DCF1FA04FB" nocase

        // Spoof file icons and extensions in Windows
        // https://github.com/henriksb/ExtensionSpoofer
        $guid_FCD5E13D_1663_4226_8280_1C6A97933AB7 = "FCD5E13D-1663-4226-8280-1C6A97933AB7" nocase

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_FCE55626_886B_4D3B_B7AA_92CECDA91514 = "FCE55626-886B-4D3B-B7AA-92CECDA91514" nocase

        // Dump the memory of a PPL with a userland exploit
        // https://github.com/itm4n/PPLdump
        $guid_FCE81BDA_ACAC_4892_969E_0414E765593B = "FCE81BDA-ACAC-4892-969E-0414E765593B" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_FD6BDF7A_FEF4_4B28_9027_5BF750F08048 = "FD6BDF7A-FEF4-4B28-9027-5BF750F08048" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_FD93D181_2EC5_4863_8A8F_5F8C84C06B35 = "FD93D181-2EC5-4863-8A8F-5F8C84C06B35" nocase

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_FDD654F5_5C54_4D93_BF8E_FAF11B00E3E9 = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" nocase

        // SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // https://github.com/GhostPack/SharpUp
        $guid_FDD654F5_5C54_4D93_BF8E_FAF11B00E3E9 = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" nocase

        // Dump cookies directly from Chrome process memory
        // https://github.com/Meckazin/ChromeKatz
        $guid_FDF5A0F3_73DA_4A8B_804F_EDD499A176EF = "FDF5A0F3-73DA-4A8B-804F-EDD499A176EF" nocase

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_FE068381_F170_4C37_82C4_11A81FE60F1A = "FE068381-F170-4C37-82C4-11A81FE60F1A" nocase

        // Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // https://github.com/Flangvik/SharpAppLocker
        $guid_FE102D27_DEC4_42E2_BF69_86C79E08B67D = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" nocase

        // creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // https://github.com/rasta-mouse/RuralBishop
        $guid_FE4414D9_1D7E_4EEB_B781_D278FE7A5619 = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" nocase

        // A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // https://github.com/hlldz/dazzleUP
        $guid_FE8F0D23_BDD1_416D_8285_F947BA86D155 = "FE8F0D23-BDD1-416D-8285-F947BA86D155" nocase

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_fea01b74_7a60_4142_a54d_7aa8f6471c00 = "fea01b74-7a60-4142-a54d-7aa8f6471c00" nocase

        // A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // https://github.com/netero1010/ScheduleRunner
        $guid_FF5F7C4C_6915_4C53_9DA3_B8BE6C5F1DB9 = "FF5F7C4C-6915-4C53-9DA3-B8BE6C5F1DB9" nocase

        // EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // https://github.com/wavestone-cdt/EDRSandblast
        $guid_FFA0FDDE_BE70_49E4_97DE_753304EF1113 = "FFA0FDDE-BE70-49E4-97DE-753304EF1113" nocase

        // Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // https://github.com/gabriellandau/EDRSandblast-GodFault
        $guid_FFA0FDDE_BE70_49E4_97DE_753304EF1113 = "FFA0FDDE-BE70-49E4-97DE-753304EF1113" nocase

        // Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // https://github.com/Meltedd/HVNC
        $guid_FFE5AD77_8AF4_4A3F_8CE7_6BDC45565F07 = "FFE5AD77-8AF4-4A3F-8CE7-6BDC45565F07" nocase


    condition:
        any of them
}
