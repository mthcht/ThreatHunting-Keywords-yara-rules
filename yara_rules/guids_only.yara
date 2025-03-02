
rule GUID_Detection
{
    meta:
        author = "@mthcht"
        description = "Detects GUIDs of offensive tools - https://github.com/BADGUIDS/badguids.github.io"
    
    strings:
        // A windows token impersonation tool
        // https://github.com/sensepost/impersonate
        $guid_00630066_0B43_474E_A93B_417CF1A65195_str = "00630066-0B43-474E-A93B-417CF1A65195" ascii wide nocase
        $guid_00630066_0B43_474E_A93B_417CF1A65195_bin = { 66 00 63 00 43 0B 4E 47 A9 3B 41 7C F1 A6 51 95 }

        // Cross-platform multi-protocol VPN software abused by attackers
        // https://github.com/SoftEtherVPN/SoftEtherVPN
        $guid_00B41CF0_7AE9_4542_9970_77B312412535_str = "00B41CF0-7AE9-4542-9970-77B312412535" ascii wide nocase
        $guid_00B41CF0_7AE9_4542_9970_77B312412535_bin = { F0 1C B4 00 E9 7A 42 45 99 70 77 B3 12 41 25 35 }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_00D7268A_92A9_4CD4_ADDF_175E9BF16AE0_str = "00D7268A-92A9-4CD4-ADDF-175E9BF16AE0" ascii wide nocase
        $guid_00D7268A_92A9_4CD4_ADDF_175E9BF16AE0_bin = { 8A 26 D7 00 A9 92 D4 4C AD DF 17 5E 9B F1 6A E0 }

        // Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // https://github.com/securesean/DecryptAutoLogon
        $guid_015A37FC_53D0_499B_BFFE_AB88C5086040_str = "015A37FC-53D0-499B-BFFE-AB88C5086040" ascii wide nocase
        $guid_015A37FC_53D0_499B_BFFE_AB88C5086040_bin = { FC 37 5A 01 D0 53 9B 49 BF FE AB 88 C5 08 60 40 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_01871B2B_B006_4069_997D_BAB3EB216160_str = "01871B2B-B006-4069-997D-BAB3EB216160" ascii wide nocase
        $guid_01871B2B_B006_4069_997D_BAB3EB216160_bin = { 2B 1B 87 01 06 B0 69 40 99 7D BA B3 EB 21 61 60 }

        // Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // https://github.com/dirkjanm/ROADtoken
        $guid_018BD6D4_9019_42FD_8D3A_831B23B47CB2_str = "018BD6D4-9019-42FD-8D3A-831B23B47CB2" ascii wide nocase
        $guid_018BD6D4_9019_42FD_8D3A_831B23B47CB2_bin = { D4 D6 8B 01 19 90 FD 42 8D 3A 83 1B 23 B4 7C B2 }

        // StandIn is a small .NET35/45 AD post-exploitation toolkit
        // https://github.com/FuzzySecurity/StandIn
        $guid_01C142BA_7AF1_48D6_B185_81147A2F7DB7_str = "01C142BA-7AF1-48D6-B185-81147A2F7DB7" ascii wide nocase
        $guid_01C142BA_7AF1_48D6_B185_81147A2F7DB7_bin = { BA 42 C1 01 F1 7A D6 48 B1 85 81 14 7A 2F 7D B7 }

        // Malware RAT with keylogger - dll injection - C2 - Remote control
        // https://github.com/sin5678/gh0st
        $guid_0228336A_2F4C_0D17_2E11_86654A1FAD8D_str = "0228336A-2F4C-0D17-2E11-86654A1FAD8D" ascii wide nocase
        $guid_0228336A_2F4C_0D17_2E11_86654A1FAD8D_bin = { 6A 33 28 02 4C 2F 17 0D 2E 11 86 65 4A 1F AD 8D }

        // remotely killing EDR with WDAC
        // https://github.com/logangoins/Krueger
        $guid_022E5A85_D732_4C5D_8CAD_A367139068D8_str = "022E5A85-D732-4C5D-8CAD-A367139068D8" ascii wide nocase
        $guid_022E5A85_D732_4C5D_8CAD_A367139068D8_bin = { 85 5A 2E 02 32 D7 5D 4C 8C AD A3 67 13 90 68 D8 }

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_023B2DB0_6DA4_4F0D_988B_4D9BF522DA37_str = "023B2DB0-6DA4-4F0D-988B-4D9BF522DA37" ascii wide nocase
        $guid_023B2DB0_6DA4_4F0D_988B_4D9BF522DA37_bin = { B0 2D 3B 02 A4 6D 0D 4F 98 8B 4D 9B F5 22 DA 37 }

        // A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // https://github.com/INotGreen/SharpThief
        $guid_025280A3_24F7_4C55_9B5E_D08124A52546_str = "025280A3-24F7-4C55-9B5E-D08124A52546" ascii wide nocase
        $guid_025280A3_24F7_4C55_9B5E_D08124A52546_bin = { A3 80 52 02 F7 24 55 4C 9B 5E D0 81 24 A5 25 46 }

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_027FAC75_3FDB_4044_8DD0_BC297BD4C461_str = "027FAC75-3FDB-4044-8DD0-BC297BD4C461" ascii wide nocase
        $guid_027FAC75_3FDB_4044_8DD0_BC297BD4C461_bin = { 75 AC 7F 02 DB 3F 44 40 8D D0 BC 29 7B D4 C4 61 }

        // Injects a DLL into a suspended process running as SYSTEM via the OfficeClickToRun service for privilege escalation - Shim Injector: Injects a DLL into a process by modifying shim data in memory without creating or registering new SDB files to evade detection.
        // https://github.com/deepinstinct/ShimMe
        $guid_0286bd5f_1a56_4251_8758_adb0338d4e98_str = "0286bd5f-1a56-4251-8758-adb0338d4e98" ascii wide nocase
        $guid_0286bd5f_1a56_4251_8758_adb0338d4e98_bin = { 5F BD 86 02 56 1A 51 42 87 58 AD B0 33 8D 4E 98 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_02948DD6_47BD_4C82_9B4B_78931DB23B8A_str = "02948DD6-47BD-4C82-9B4B-78931DB23B8A" ascii wide nocase
        $guid_02948DD6_47BD_4C82_9B4B_78931DB23B8A_bin = { D6 8D 94 02 BD 47 82 4C 9B 4B 78 93 1D B2 3B 8A }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_02EF15C0_BA19_4115_BB7F_F5B04F7087FE_str = "02EF15C0-BA19-4115-BB7F-F5B04F7087FE" ascii wide nocase
        $guid_02EF15C0_BA19_4115_BB7F_F5B04F7087FE_bin = { C0 15 EF 02 19 BA 15 41 BB 7F F5 B0 4F 70 87 FE }

        // automate abuse of clickonce applications
        // https://github.com/trustedsec/The_Shelf
        $guid_02FAF312_BF2A_466B_8AD2_1339A31C303B_str = "02FAF312-BF2A-466B-8AD2-1339A31C303B" ascii wide nocase
        $guid_02FAF312_BF2A_466B_8AD2_1339A31C303B_bin = { 12 F3 FA 02 2A BF 6B 46 8A D2 13 39 A3 1C 30 3B }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_034B1C28_96B9_486A_B238_9C651EAA32CA_str = "034B1C28-96B9-486A-B238-9C651EAA32CA" ascii wide nocase
        $guid_034B1C28_96B9_486A_B238_9C651EAA32CA_bin = { 28 1C 4B 03 B9 96 6A 48 B2 38 9C 65 1E AA 32 CA }

        // SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // https://github.com/Mayyhem/SharpSCCM/
        $guid_03652836_898E_4A9F_B781_B7D86E750F60_str = "03652836-898E-4A9F-B781-B7D86E750F60" ascii wide nocase
        $guid_03652836_898E_4A9F_B781_B7D86E750F60_bin = { 36 28 65 03 8E 89 9F 4A B7 81 B7 D8 6E 75 0F 60 }

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_03A09084_0576_45C5_97CA_B83B1A8688B8_str = "03A09084-0576-45C5-97CA-B83B1A8688B8" ascii wide nocase
        $guid_03A09084_0576_45C5_97CA_B83B1A8688B8_bin = { 84 90 A0 03 76 05 C5 45 97 CA B8 3B 1A 86 88 B8 }

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D_str = "042BF22B-7728-486B-B8C9-D5B91733C46D" ascii wide nocase
        $guid_042BF22B_7728_486B_B8C9_D5B91733C46D_bin = { 2B F2 2B 04 28 77 6B 48 B8 C9 D5 B9 17 33 C4 6D }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_043EE329_C00A_4F67_971F_BF1C55D4BC1A_str = "043EE329-C00A-4F67-971F-BF1C55D4BC1A" ascii wide nocase
        $guid_043EE329_C00A_4F67_971F_BF1C55D4BC1A_bin = { 29 E3 3E 04 0A C0 67 4F 97 1F BF 1C 55 D4 BC 1A }

        // unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $guid_0472A393_9503_491D_B6DA_FA47CD567EDE_str = "0472A393-9503-491D-B6DA-FA47CD567EDE" ascii wide nocase
        $guid_0472A393_9503_491D_B6DA_FA47CD567EDE_bin = { 93 A3 72 04 03 95 1D 49 B6 DA FA 47 CD 56 7E DE }

        // EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // https://github.com/wavestone-cdt/EDRSandblast
        $guid_04DFB6E4_809E_4C35_88A1_2CC5F1EBFEBD_str = "04DFB6E4-809E-4C35-88A1-2CC5F1EBFEBD" ascii wide nocase
        $guid_04DFB6E4_809E_4C35_88A1_2CC5F1EBFEBD_bin = { E4 B6 DF 04 9E 80 35 4C 88 A1 2C C5 F1 EB FE BD }

        // Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // https://github.com/daem0nc0re/PrivFu
        $guid_04FC654C_D89A_44F9_9E34_6D95CE152E9D_str = "04FC654C-D89A-44F9-9E34-6D95CE152E9D" ascii wide nocase
        $guid_04FC654C_D89A_44F9_9E34_6D95CE152E9D_bin = { 4C 65 FC 04 9A D8 F9 44 9E 34 6D 95 CE 15 2E 9D }

        // Windows Privilege Escalation Exploit BadPotato
        // https://github.com/BeichenDream/BadPotato
        $guid_0527a14f_1591_4d94_943e_d6d784a50549_str = "0527a14f-1591-4d94-943e-d6d784a50549" ascii wide nocase
        $guid_0527a14f_1591_4d94_943e_d6d784a50549_bin = { 4F A1 27 05 91 15 94 4D 94 3E D6 D7 84 A5 05 49 }

        // RevengeRAT - AsyncRAT  Simple RAT
        // https://github.com/NYAN-x-CAT/RevengeRAT-Stub-Cssharp
        $guid_052C26C0_7979_4555_89CE_34C5CE8D8B34_str = "052C26C0-7979-4555-89CE-34C5CE8D8B34" ascii wide nocase
        $guid_052C26C0_7979_4555_89CE_34C5CE8D8B34_bin = { C0 26 2C 05 79 79 55 45 89 CE 34 C5 CE 8D 8B 34 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_055BC73F_FCAE_4361_B035_2E156A101EA9_str = "055BC73F-FCAE-4361-B035-2E156A101EA9" ascii wide nocase
        $guid_055BC73F_FCAE_4361_B035_2E156A101EA9_bin = { 3F C7 5B 05 AE FC 61 43 B0 35 2E 15 6A 10 1E A9 }

        // Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // https://github.com/XaFF-XaFF/Cronos-Rootkit
        $guid_05B4EB7F_3D59_4E6A_A7BC_7C1241578CA7_str = "05B4EB7F-3D59-4E6A-A7BC-7C1241578CA7" ascii wide nocase
        $guid_05B4EB7F_3D59_4E6A_A7BC_7C1241578CA7_bin = { 7F EB B4 05 59 3D 6A 4E A7 BC 7C 12 41 57 8C A7 }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_06AF1D64_F2FC_4767_8794_7313C7BB0A40_str = "06AF1D64-F2FC-4767-8794-7313C7BB0A40" ascii wide nocase
        $guid_06AF1D64_F2FC_4767_8794_7313C7BB0A40_bin = { 64 1D AF 06 FC F2 67 47 87 94 73 13 C7 BB 0A 40 }

        // *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // https://github.com/logangoins/Cable
        $guid_06B2AE2B_7FD3_4C36_B825_1594752B1D7B_str = "06B2AE2B-7FD3-4C36-B825-1594752B1D7B" ascii wide nocase
        $guid_06B2AE2B_7FD3_4C36_B825_1594752B1D7B_bin = { 2B AE B2 06 D3 7F 36 4C B8 25 15 94 75 2B 1D 7B }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_06B2B14A_CE87_41C0_A77A_2644FE3231C7_str = "06B2B14A-CE87-41C0-A77A-2644FE3231C7" ascii wide nocase
        $guid_06B2B14A_CE87_41C0_A77A_2644FE3231C7_bin = { 4A B1 B2 06 87 CE C0 41 A7 7A 26 44 FE 32 31 C7 }

        // .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // https://github.com/notdodo/LocalAdminSharp
        $guid_07628592_5A22_4C0A_9330_6C90BD7A94B6_str = "07628592-5A22-4C0A-9330-6C90BD7A94B6" ascii wide nocase
        $guid_07628592_5A22_4C0A_9330_6C90BD7A94B6_bin = { 92 85 62 07 22 5A 0A 4C 93 30 6C 90 BD 7A 94 B6 }

        // Terminate AV/EDR leveraging BYOVD attack
        // https://github.com/dmcxblue/SharpBlackout
        $guid_07DFC5AA_5B1F_4CCC_A3D3_816ECCBB6CB6_str = "07DFC5AA-5B1F-4CCC-A3D3-816ECCBB6CB6" ascii wide nocase
        $guid_07DFC5AA_5B1F_4CCC_A3D3_816ECCBB6CB6_bin = { AA C5 DF 07 1F 5B CC 4C A3 D3 81 6E CC BB 6C B6 }

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_07EF7652_1C2D_478B_BB4B_F9560695A387_str = "07EF7652-1C2D-478B-BB4B-F9560695A387" ascii wide nocase
        $guid_07EF7652_1C2D_478B_BB4B_F9560695A387_bin = { 52 76 EF 07 2D 1C 8B 47 BB 4B F9 56 06 95 A3 87 }

        // Metasploit is a widely-used. open-source framework designed for penetration testing. vulnerability assessment. and exploit development. It provides security professionals and researchers with a comprehensive platform to discover. exploit. and validate vulnerabilities in computer systems and networks. Metasploit includes a large database of pre-built exploits. payloads. and auxiliary modules that can be used to test various attack vectors. identify security weaknesses. and simulate real-world cyberattacks. By utilizing Metasploit. security teams can better understand potential threats and improve their overall security posture.
        // https://github.com/rapid7/metasploit-omnibus
        $guid_080A880D_BA94_4CF8_9015_5B2063073E02_str = "080A880D-BA94-4CF8-9015-5B2063073E02" ascii wide nocase
        $guid_080A880D_BA94_4CF8_9015_5B2063073E02_bin = { 0D 88 0A 08 94 BA F8 4C 90 15 5B 20 63 07 3E 02 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_0845B3E9_B6AE_4227_B484_CECBC2EB1C87_str = "0845B3E9-B6AE-4227-B484-CECBC2EB1C87" ascii wide nocase
        $guid_0845B3E9_B6AE_4227_B484_CECBC2EB1C87_bin = { E9 B3 45 08 AE B6 27 42 B4 84 CE CB C2 EB 1C 87 }

        // An open-source windows defender manager. Now you can disable windows defender permanently
        // https://github.com/pgkt04/defender-control
        $guid_089CA7D6_3277_4998_86AF_F6413290A442_str = "089CA7D6-3277-4998-86AF-F6413290A442" ascii wide nocase
        $guid_089CA7D6_3277_4998_86AF_F6413290A442_bin = { D6 A7 9C 08 77 32 98 49 86 AF F6 41 32 90 A4 42 }

        // Extract Windows Defender database from vdm files and unpack it
        // https://github.com/hfiref0x/WDExtract/
        $guid_08AEC00F_42ED_4E62_AE8D_0BFCE30A3F57_str = "08AEC00F-42ED-4E62-AE8D-0BFCE30A3F57" ascii wide nocase
        $guid_08AEC00F_42ED_4E62_AE8D_0BFCE30A3F57_bin = { 0F C0 AE 08 ED 42 62 4E AE 8D 0B FC E3 0A 3F 57 }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_08DBC2BF_E9F3_4AE4_B0CC_6E9C8767982D_str = "08DBC2BF-E9F3-4AE4-B0CC-6E9C8767982D" ascii wide nocase
        $guid_08DBC2BF_E9F3_4AE4_B0CC_6E9C8767982D_bin = { BF C2 DB 08 F3 E9 E4 4A B0 CC 6E 9C 87 67 98 2D }

        // COM-hunter is a COM Hijacking persistnce tool written in C#
        // https://github.com/nickvourd/COM-Hunter
        $guid_09323E4D_BE0F_452A_9CA8_B07D2CFA9804_str = "09323E4D-BE0F-452A-9CA8-B07D2CFA9804" ascii wide nocase
        $guid_09323E4D_BE0F_452A_9CA8_B07D2CFA9804_bin = { 4D 3E 32 09 0F BE 2A 45 9C A8 B0 7D 2C FA 98 04 }

        // From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // https://github.com/mpgn/BackupOperatorToDA
        $guid_0971A047_A45A_43F4_B7D8_16AC1114B524_str = "0971A047-A45A-43F4-B7D8-16AC1114B524" ascii wide nocase
        $guid_0971A047_A45A_43F4_B7D8_16AC1114B524_bin = { 47 A0 71 09 5A A4 F4 43 B7 D8 16 AC 11 14 B5 24 }

        // A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // https://github.com/ShorSec/DllNotificationInjection
        $guid_0A1C2C46_33F7_4D4C_B8C6_1FC9B116A6DF_str = "0A1C2C46-33F7-4D4C-B8C6-1FC9B116A6DF" ascii wide nocase
        $guid_0A1C2C46_33F7_4D4C_B8C6_1FC9B116A6DF_bin = { 46 2C 1C 0A F7 33 4C 4D B8 C6 1F C9 B1 16 A6 DF }

        // erase specified records from Windows event logs
        // https://github.com/QAX-A-Team/EventCleaner
        $guid_0A2B3F8A_EDC2_48B5_A5FC_DE2AC57C8990_str = "0A2B3F8A-EDC2-48B5-A5FC-DE2AC57C8990" ascii wide nocase
        $guid_0A2B3F8A_EDC2_48B5_A5FC_DE2AC57C8990_bin = { 8A 3F 2B 0A C2 ED B5 48 A5 FC DE 2A C5 7C 89 90 }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_0A78E156_D03F_4667_B70E_4E9B4AA1D491_str = "0A78E156-D03F-4667-B70E-4E9B4AA1D491" ascii wide nocase
        $guid_0A78E156_D03F_4667_B70E_4E9B4AA1D491_bin = { 56 E1 78 0A 3F D0 67 46 B7 0E 4E 9B 4A A1 D4 91 }

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_0ABB9F2A_6913_4174_9431_851F9D3E94B4_str = "0ABB9F2A-6913-4174-9431-851F9D3E94B4" ascii wide nocase
        $guid_0ABB9F2A_6913_4174_9431_851F9D3E94B4_bin = { 2A 9F BB 0A 13 69 74 41 94 31 85 1F 9D 3E 94 B4 }

        // Manipulating and Abusing Windows Access Tokens
        // https://github.com/S1ckB0y1337/TokenPlayer
        $guid_0ADFD1F0_7C15_4A22_87B4_F67E046ECD96_str = "0ADFD1F0-7C15-4A22-87B4-F67E046ECD96" ascii wide nocase
        $guid_0ADFD1F0_7C15_4A22_87B4_F67E046ECD96_bin = { F0 D1 DF 0A 15 7C 22 4A 87 B4 F6 7E 04 6E CD 96 }

        // The OpenBullet web testing application.
        // https://github.com/openbullet/openbullet
        $guid_0B6D8B01_861E_4CAF_B1C9_6670884381DB_str = "0B6D8B01-861E-4CAF-B1C9-6670884381DB" ascii wide nocase
        $guid_0B6D8B01_861E_4CAF_B1C9_6670884381DB_bin = { 01 8B 6D 0B 1E 86 AF 4C B1 C9 66 70 88 43 81 DB }

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_0BD5DE6B_8DA5_4CF1_AE53_A265010F52AA_str = "0BD5DE6B-8DA5-4CF1-AE53-A265010F52AA" ascii wide nocase
        $guid_0BD5DE6B_8DA5_4CF1_AE53_A265010F52AA_bin = { 6B DE D5 0B A5 8D F1 4C AE 53 A2 65 01 0F 52 AA }

        // a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // https://github.com/malcomvetter/UnstoppableService
        $guid_0C117EE5_2A21_496D_AF31_8CC7F0CAAA86_str = "0C117EE5-2A21-496D-AF31-8CC7F0CAAA86" ascii wide nocase
        $guid_0C117EE5_2A21_496D_AF31_8CC7F0CAAA86_bin = { E5 7E 11 0C 21 2A 6D 49 AF 31 8C C7 F0 CA AA 86 }

        // Extracts passwords from a KeePass 2.x database directly from memory
        // https://github.com/denandz/KeeFarce
        $guid_0C3EB2F7_92BA_4895_99FC_7098A16FFE8C_str = "0C3EB2F7-92BA-4895-99FC-7098A16FFE8C" ascii wide nocase
        $guid_0C3EB2F7_92BA_4895_99FC_7098A16FFE8C_bin = { F7 B2 3E 0C BA 92 95 48 99 FC 70 98 A1 6F FE 8C }

        // Dump cookies directly from Chrome process memory
        // https://github.com/Meckazin/ChromeKatz
        $guid_0C81C7D4_736A_4876_A36E_15E5B2EF5117_str = "0C81C7D4-736A-4876-A36E-15E5B2EF5117" ascii wide nocase
        $guid_0C81C7D4_736A_4876_A36E_15E5B2EF5117_bin = { D4 C7 81 0C 6A 73 76 48 A3 6E 15 E5 B2 EF 51 17 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_0C89EC7D_AC60_4591_8F6B_CB5F20EC0D8D_str = "0C89EC7D-AC60-4591-8F6B-CB5F20EC0D8D" ascii wide nocase
        $guid_0C89EC7D_AC60_4591_8F6B_CB5F20EC0D8D_bin = { 7D EC 89 0C 60 AC 91 45 8F 6B CB 5F 20 EC 0D 8D }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_0C8F49D8_BD68_420A_907D_031B83737C50_str = "0C8F49D8-BD68-420A-907D-031B83737C50" ascii wide nocase
        $guid_0C8F49D8_BD68_420A_907D_031B83737C50_bin = { D8 49 8F 0C 68 BD 0A 42 90 7D 03 1B 83 73 7C 50 }

        // ArtsOfGetSystem privesc tools
        // https://github.com/daem0nc0re/PrivFu/
        $guid_0CC923FB_E1FD_456B_9FE4_9EBA5A3DC2FC_str = "0CC923FB-E1FD-456B-9FE4-9EBA5A3DC2FC" ascii wide nocase
        $guid_0CC923FB_E1FD_456B_9FE4_9EBA5A3DC2FC_bin = { FB 23 C9 0C FD E1 6B 45 9F E4 9E BA 5A 3D C2 FC }

        // PrintNightmare exploitation
        // https://github.com/outflanknl/PrintNightmare
        $guid_0CD16C7B_2A65_44E5_AB74_843BD23241D3_str = "0CD16C7B-2A65-44E5-AB74-843BD23241D3" ascii wide nocase
        $guid_0CD16C7B_2A65_44E5_AB74_843BD23241D3_bin = { 7B 6C D1 0C 65 2A E5 44 AB 74 84 3B D2 32 41 D3 }

        // Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // https://github.com/zer0condition/mhydeath
        $guid_0D17A4B4_A7C4_49C0_99E3_B856F9F3B271_str = "0D17A4B4-A7C4-49C0-99E3-B856F9F3B271" ascii wide nocase
        $guid_0D17A4B4_A7C4_49C0_99E3_B856F9F3B271_bin = { B4 A4 17 0D C4 A7 C0 49 99 E3 B8 56 F9 F3 B2 71 }

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_0DD419E5_D7B3_4360_874E_5838A7519355_str = "0DD419E5-D7B3-4360-874E-5838A7519355" ascii wide nocase
        $guid_0DD419E5_D7B3_4360_874E_5838A7519355_bin = { E5 19 D4 0D B3 D7 60 43 87 4E 58 38 A7 51 93 55 }

        // Open-Source Remote Administration Tool For Windows C# (RAT)
        // https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $guid_0DE8DA5D_061D_4649_8A56_48729CF1F789_str = "0DE8DA5D-061D-4649-8A56-48729CF1F789" ascii wide nocase
        $guid_0DE8DA5D_061D_4649_8A56_48729CF1F789_bin = { 5D DA E8 0D 1D 06 49 46 8A 56 48 72 9C F1 F7 89 }

        // Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // https://github.com/CCob/Volumiser
        $guid_0DF38AD4_60AF_4F93_9C7A_7FB7BA692017_str = "0DF38AD4-60AF-4F93-9C7A-7FB7BA692017" ascii wide nocase
        $guid_0DF38AD4_60AF_4F93_9C7A_7FB7BA692017_bin = { D4 8A F3 0D AF 60 93 4F 9C 7A 7F B7 BA 69 20 17 }

        // Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // https://github.com/ricardojoserf/NativeDump
        $guid_0DF612AE_47D8_422C_B0C5_0727EA60784F_str = "0DF612AE-47D8-422C-B0C5-0727EA60784F" ascii wide nocase
        $guid_0DF612AE_47D8_422C_B0C5_0727EA60784F_bin = { AE 12 F6 0D D8 47 2C 42 B0 C5 07 27 EA 60 78 4F }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_0E423DD6_FAAF_4A66_8828_6A5A5F22269B_str = "0E423DD6-FAAF-4A66-8828-6A5A5F22269B" ascii wide nocase
        $guid_0E423DD6_FAAF_4A66_8828_6A5A5F22269B_bin = { D6 3D 42 0E AF FA 66 4A 88 28 6A 5A 5F 22 26 9B }

        // EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // https://github.com/Mattiwatti/EfiGuard
        $guid_0E4BAB8F_E6E0_47A8_8E99_8D451839967E_str = "0E4BAB8F-E6E0-47A8-8E99-8D451839967E" ascii wide nocase
        $guid_0E4BAB8F_E6E0_47A8_8E99_8D451839967E_bin = { 8F AB 4B 0E E0 E6 A8 47 8E 99 8D 45 18 39 96 7E }

        // active directory weakness scan Vulnerability scanner
        // https://github.com/netwrix/pingcastle
        $guid_0E5D043A_CAA1_40C7_A616_773F347FA43F_str = "0E5D043A-CAA1-40C7-A616-773F347FA43F" ascii wide nocase
        $guid_0E5D043A_CAA1_40C7_A616_773F347FA43F_bin = { 3A 04 5D 0E A1 CA C7 40 A6 16 77 3F 34 7F A4 3F }

        // A New Exploitation Technique for Visual Studio Projects
        // https://github.com/cjm00n/EvilSln
        $guid_0FE0D049_F352_477D_BCCD_ACBF7D4F6F15_str = "0FE0D049-F352-477D-BCCD-ACBF7D4F6F15" ascii wide nocase
        $guid_0FE0D049_F352_477D_BCCD_ACBF7D4F6F15_bin = { 49 D0 E0 0F 52 F3 7D 47 BC CD AC BF 7D 4F 6F 15 }

        // Windows Local Privilege Escalation from Service Account to System
        // https://github.com/antonioCoco/RoguePotato
        $guid_105C2C6D_1C0A_4535_A231_80E355EFB112_str = "105C2C6D-1C0A-4535-A231-80E355EFB112" ascii wide nocase
        $guid_105C2C6D_1C0A_4535_A231_80E355EFB112_bin = { 6D 2C 5C 10 0A 1C 35 45 A2 31 80 E3 55 EF B1 12 }

        // A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // https://github.com/cybersectroll/SharpPersistSD
        $guid_107EBC1B_0273_4B3D_B676_DE64B7F52B33_str = "107EBC1B-0273-4B3D-B676-DE64B7F52B33" ascii wide nocase
        $guid_107EBC1B_0273_4B3D_B676_DE64B7F52B33_bin = { 1B BC 7E 10 73 02 3D 4B B6 76 DE 64 B7 F5 2B 33 }

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_10CC4D5B_DC87_4AEB_887B_E47367BF656B_str = "10CC4D5B-DC87-4AEB-887B-E47367BF656B" ascii wide nocase
        $guid_10CC4D5B_DC87_4AEB_887B_E47367BF656B_bin = { 5B 4D CC 10 87 DC EB 4A 88 7B E4 73 67 BF 65 6B }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_111BB935_2A0A_4AE2_AEB0_EF2FAA529840_str = "111BB935-2A0A-4AE2-AEB0-EF2FAA529840" ascii wide nocase
        $guid_111BB935_2A0A_4AE2_AEB0_EF2FAA529840_bin = { 35 B9 1B 11 0A 2A E2 4A AE B0 EF 2F AA 52 98 40 }

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_11385CC1_54B7_4968_9052_DF8BB1961F1E_str = "11385CC1-54B7-4968-9052-DF8BB1961F1E" ascii wide nocase
        $guid_11385CC1_54B7_4968_9052_DF8BB1961F1E_bin = { C1 5C 38 11 B7 54 68 49 90 52 DF 8B B1 96 1F 1E }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_116472CE_3924_40EA_90F9_50A1A00D0EC5_str = "116472CE-3924-40EA-90F9-50A1A00D0EC5" ascii wide nocase
        $guid_116472CE_3924_40EA_90F9_50A1A00D0EC5_bin = { CE 72 64 11 24 39 EA 40 90 F9 50 A1 A0 0D 0E C5 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_1250BAE1_D26F_4EF2_9452_9B5009568336_str = "1250BAE1-D26F-4EF2-9452-9B5009568336" ascii wide nocase
        $guid_1250BAE1_D26F_4EF2_9452_9B5009568336_bin = { E1 BA 50 12 6F D2 F2 4E 94 52 9B 50 09 56 83 36 }

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_128C450F_C8B3_403A_9D0C_E5AD6B7F566F_str = "128C450F-C8B3-403A-9D0C-E5AD6B7F566F" ascii wide nocase
        $guid_128C450F_C8B3_403A_9D0C_E5AD6B7F566F_bin = { 0F 45 8C 12 B3 C8 3A 40 9D 0C E5 AD 6B 7F 56 6F }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_13431429_2DB6_480F_B73F_CA019FE759E3_str = "13431429-2DB6-480F-B73F-CA019FE759E3" ascii wide nocase
        $guid_13431429_2DB6_480F_B73F_CA019FE759E3_bin = { 29 14 43 13 B6 2D 0F 48 B7 3F CA 01 9F E7 59 E3 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_13A59BB8_0246_4FFA_951B_89B9A341F159_str = "13A59BB8-0246-4FFA-951B-89B9A341F159" ascii wide nocase
        $guid_13A59BB8_0246_4FFA_951B_89B9A341F159_bin = { B8 9B A5 13 46 02 FA 4F 95 1B 89 B9 A3 41 F1 59 }

        // Nidhogg is an all-in-one simple to use rootkit for red teams.
        // https://github.com/Idov31/Nidhogg
        $guid_13C57810_FF18_4258_ABC9_935040A54F0B_str = "13C57810-FF18-4258-ABC9-935040A54F0B" ascii wide nocase
        $guid_13C57810_FF18_4258_ABC9_935040A54F0B_bin = { 10 78 C5 13 18 FF 58 42 AB C9 93 50 40 A5 4F 0B }

        // SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // https://github.com/grayhatkiller/SharpExShell
        $guid_13C84182_2F5F_4EE8_A37A_4483E7E57154_str = "13C84182-2F5F-4EE8-A37A-4483E7E57154" ascii wide nocase
        $guid_13C84182_2F5F_4EE8_A37A_4483E7E57154_bin = { 82 41 C8 13 5F 2F E8 4E A3 7A 44 83 E7 E5 71 54 }

        // XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // https://github.com/FSecureLABS/Xrulez
        $guid_14083A04_DD4B_4E7D_A16E_86947D3D6D74_str = "14083A04-DD4B-4E7D-A16E-86947D3D6D74" ascii wide nocase
        $guid_14083A04_DD4B_4E7D_A16E_86947D3D6D74_bin = { 04 3A 08 14 4B DD 7D 4E A1 6E 86 94 7D 3D 6D 74 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_14CA405B_8BAC_48AB_9FBA_8FB5DF88FD0D_str = "14CA405B-8BAC-48AB-9FBA-8FB5DF88FD0D" ascii wide nocase
        $guid_14CA405B_8BAC_48AB_9FBA_8FB5DF88FD0D_bin = { 5B 40 CA 14 AC 8B AB 48 9F BA 8F B5 DF 88 FD 0D }

        // exploit for CVE-2020-1472
        // https://github.com/leitosama/SharpZeroLogon
        $guid_15ce9a3c_4609_4184_87b2_e29fc5e2b770_str = "15ce9a3c-4609-4184-87b2-e29fc5e2b770" ascii wide nocase
        $guid_15ce9a3c_4609_4184_87b2_e29fc5e2b770_bin = { 3C 9A CE 15 09 46 84 41 87 B2 E2 9F C5 E2 B7 70 }

        // Injects a DLL into a suspended process running as SYSTEM via the OfficeClickToRun service for privilege escalation - Shim Injector: Injects a DLL into a process by modifying shim data in memory without creating or registering new SDB files to evade detection.
        // https://github.com/deepinstinct/ShimMe
        $guid_1605d453_7d62_4198_a436_27e48ef828eb_str = "1605d453-7d62-4198-a436-27e48ef828eb" ascii wide nocase
        $guid_1605d453_7d62_4198_a436_27e48ef828eb_bin = { 53 D4 05 16 62 7D 98 41 A4 36 27 E4 8E F8 28 EB }

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_1617117C_0E94_4E6A_922C_836D616EC1F5_str = "1617117C-0E94-4E6A-922C-836D616EC1F5" ascii wide nocase
        $guid_1617117C_0E94_4E6A_922C_836D616EC1F5_bin = { 7C 11 17 16 94 0E 6A 4E 92 2C 83 6D 61 6E C1 F5 }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_1659E645_27B0_4AB9_A10E_64BA4B801CB0_str = "1659E645-27B0-4AB9-A10E-64BA4B801CB0" ascii wide nocase
        $guid_1659E645_27B0_4AB9_A10E_64BA4B801CB0_bin = { 45 E6 59 16 B0 27 B9 4A A1 0E 64 BA 4B 80 1C B0 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_171A9A71_EDEF_4891_9828_44434A00585E_str = "171A9A71-EDEF-4891-9828-44434A00585E" ascii wide nocase
        $guid_171A9A71_EDEF_4891_9828_44434A00585E_bin = { 71 9A 1A 17 EF ED 91 48 98 28 44 43 4A 00 58 5E }

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_17332F12_D796_42D1_9A3E_460590A49382_str = "17332F12-D796-42D1-9A3E-460590A49382" ascii wide nocase
        $guid_17332F12_D796_42D1_9A3E_460590A49382_bin = { 12 2F 33 17 96 D7 D1 42 9A 3E 46 05 90 A4 93 82 }

        // Extracts passwords from a KeePass 2.x database directly from memory
        // https://github.com/denandz/KeeFarce
        $guid_17589EA6_FCC9_44BB_92AD_D5B3EEA6AF03_str = "17589EA6-FCC9-44BB-92AD-D5B3EEA6AF03" ascii wide nocase
        $guid_17589EA6_FCC9_44BB_92AD_D5B3EEA6AF03_bin = { A6 9E 58 17 C9 FC BB 44 92 AD D5 B3 EE A6 AF 03 }

        // mimikatz UUID
        // https://github.com/gentilkiwi/mimikatz
        $guid_17FC11E9_C258_4B8D_8D07_2F4125156244_str = "17FC11E9-C258-4B8D-8D07-2F4125156244" ascii wide nocase
        $guid_17FC11E9_C258_4B8D_8D07_2F4125156244_bin = { E9 11 FC 17 58 C2 8D 4B 8D 07 2F 41 25 15 62 44 }

        // Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // https://github.com/RowTeam/SharpDecryptPwd
        $guid_1824ED63_BE4D_4306_919D_9C749C1AE271_str = "1824ED63-BE4D-4306-919D-9C749C1AE271" ascii wide nocase
        $guid_1824ED63_BE4D_4306_919D_9C749C1AE271_bin = { 63 ED 24 18 4D BE 06 43 91 9D 9C 74 9C 1A E2 71 }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_189219A1_9A2A_4B09_8F69_6207E9996F94_str = "189219A1-9A2A-4B09-8F69-6207E9996F94" ascii wide nocase
        $guid_189219A1_9A2A_4B09_8F69_6207E9996F94_bin = { A1 19 92 18 2A 9A 09 4B 8F 69 62 07 E9 99 6F 94 }

        // Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // https://github.com/OmerYa/Invisi-Shell
        $guid_18A66118_B98D_4FFC_AABE_DAFF5779F14C_str = "18A66118-B98D-4FFC-AABE-DAFF5779F14C" ascii wide nocase
        $guid_18A66118_B98D_4FFC_AABE_DAFF5779F14C_bin = { 18 61 A6 18 8D B9 FC 4F AA BE DA FF 57 79 F1 4C }

        // proof-of-concept of Process Forking.
        // https://github.com/D4stiny/ForkPlayground
        $guid_18C681A2_072F_49D5_9DE6_74C979EAE08B_str = "18C681A2-072F-49D5-9DE6-74C979EAE08B" ascii wide nocase
        $guid_18C681A2_072F_49D5_9DE6_74C979EAE08B_bin = { A2 81 C6 18 2F 07 D5 49 9D E6 74 C9 79 EA E0 8B }

        // C++ stealer (passwords - cookies - forms - cards - wallets) 
        // https://github.com/SecUser1/PredatorTheStealer
        $guid_190DFAEB_0288_4043_BE0E_3273FA653B52_str = "190DFAEB-0288-4043-BE0E-3273FA653B52" ascii wide nocase
        $guid_190DFAEB_0288_4043_BE0E_3273FA653B52_bin = { EB FA 0D 19 88 02 43 40 BE 0E 32 73 FA 65 3B 52 }

        // A C# Command & Control framework
        // https://github.com/DragoQCC/HardHatC2
        $guid_196B8469_F798_4ECC_9A77_C1CAB5BF6EAE_str = "196B8469-F798-4ECC-9A77-C1CAB5BF6EAE" ascii wide nocase
        $guid_196B8469_F798_4ECC_9A77_C1CAB5BF6EAE_bin = { 69 84 6B 19 98 F7 CC 4E 9A 77 C1 CA B5 BF 6E AE }

        // DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // https://github.com/dafthack/DomainPasswordSpray
        $guid_1a3c4069_8c11_4336_bef8_9a43c0ba60e2_str = "1a3c4069-8c11-4336-bef8-9a43c0ba60e2" ascii wide nocase
        $guid_1a3c4069_8c11_4336_bef8_9a43c0ba60e2_bin = { 69 40 3C 1A 11 8C 36 43 BE F8 9A 43 C0 BA 60 E2 }

        // registry manipulation to create scheduled tasks without triggering the usual event logs.
        // https://github.com/dmcxblue/SharpGhostTask
        $guid_1A8C9BD8_1800_46B0_8E22_7D3823C68366_str = "1A8C9BD8-1800-46B0-8E22-7D3823C68366" ascii wide nocase
        $guid_1A8C9BD8_1800_46B0_8E22_7D3823C68366_bin = { D8 9B 8C 1A 00 18 B0 46 8E 22 7D 38 23 C6 83 66 }

        // simple POC to show how to tunnel traffic through Azure Application Proxy
        // https://github.com/xpn/AppProxyC2
        $guid_1A99EBED_6E53_469F_88B7_F4C3D2C96B07_str = "1A99EBED-6E53-469F-88B7-F4C3D2C96B07" ascii wide nocase
        $guid_1A99EBED_6E53_469F_88B7_F4C3D2C96B07_bin = { ED EB 99 1A 53 6E 9F 46 88 B7 F4 C3 D2 C9 6B 07 }

        // Proof of concept code for thread pool based process injection in Windows.
        // https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $guid_1AFD1BA3_028A_4E0F_82A8_095F38694ECF_str = "1AFD1BA3-028A-4E0F-82A8-095F38694ECF" ascii wide nocase
        $guid_1AFD1BA3_028A_4E0F_82A8_095F38694ECF_bin = { A3 1B FD 1A 8A 02 0F 4E 82 A8 09 5F 38 69 4E CF }

        // Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // https://github.com/itm4n/Perfusion
        $guid_1B1F64B3_B8A4_4BBB_BB66_F020E2D4F288_str = "1B1F64B3-B8A4-4BBB-BB66-F020E2D4F288" ascii wide nocase
        $guid_1B1F64B3_B8A4_4BBB_BB66_F020E2D4F288_bin = { B3 64 1F 1B A4 B8 BB 4B BB 66 F0 20 E2 D4 F2 88 }

        // The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // https://github.com/decoder-it/LocalPotato
        $guid_1B3C96A3_F698_472B_B786_6FED7A205159_str = "1B3C96A3-F698-472B-B786-6FED7A205159" ascii wide nocase
        $guid_1B3C96A3_F698_472B_B786_6FED7A205159_bin = { A3 96 3C 1B 98 F6 2B 47 B7 86 6F ED 7A 20 51 59 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_1B454840_E496_4F27_AA18_439A4E97BCC6_str = "1B454840-E496-4F27-AA18-439A4E97BCC6" ascii wide nocase
        $guid_1B454840_E496_4F27_AA18_439A4E97BCC6_bin = { 40 48 45 1B 96 E4 27 4F AA 18 43 9A 4E 97 BC C6 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_1B52A3D9_014C_4CBF_BB98_09080D9A8D16_str = "1B52A3D9-014C-4CBF-BB98-09080D9A8D16" ascii wide nocase
        $guid_1B52A3D9_014C_4CBF_BB98_09080D9A8D16_bin = { D9 A3 52 1B 4C 01 BF 4C BB 98 09 08 0D 9A 8D 16 }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_1BA54A13_B390_47B3_9628_B58A2BBA193B_str = "1BA54A13-B390-47B3-9628-B58A2BBA193B" ascii wide nocase
        $guid_1BA54A13_B390_47B3_9628_B58A2BBA193B_bin = { 13 4A A5 1B 90 B3 B3 47 96 28 B5 8A 2B BA 19 3B }

        // Proof-of-Concept for CVE-2023-38146
        // https://github.com/gabe-k/themebleed
        $guid_1BACEDDC_CD87_41DC_948C_1C12F960BECB_str = "1BACEDDC-CD87-41DC-948C-1C12F960BECB" ascii wide nocase
        $guid_1BACEDDC_CD87_41DC_948C_1C12F960BECB_bin = { DC ED AC 1B 87 CD DC 41 94 8C 1C 12 F9 60 BE CB }

        // Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // https://github.com/CCob/SweetPotato
        $guid_1BF9C10F_6F89_4520_9D2E_AAF17D17BA5E_str = "1BF9C10F-6F89-4520-9D2E-AAF17D17BA5E" ascii wide nocase
        $guid_1BF9C10F_6F89_4520_9D2E_AAF17D17BA5E_bin = { 0F C1 F9 1B 89 6F 20 45 9D 2E AA F1 7D 17 BA 5E }

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_1c50adeb_53ac_41b9_9c34_7045cffbae45_str = "1c50adeb-53ac-41b9-9c34-7045cffbae45" ascii wide nocase
        $guid_1c50adeb_53ac_41b9_9c34_7045cffbae45_bin = { EB AD 50 1C AC 53 B9 41 9C 34 70 45 CF FB AE 45 }

        // unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $guid_1C5EDA8C_D27F_44A4_A156_6F863477194D_str = "1C5EDA8C-D27F-44A4-A156-6F863477194D" ascii wide nocase
        $guid_1C5EDA8C_D27F_44A4_A156_6F863477194D_bin = { 8C DA 5E 1C 7F D2 A4 44 A1 56 6F 86 34 77 19 4D }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_1CC6E8A9_1875_430C_B2BB_F227ACD711B1_str = "1CC6E8A9-1875-430C-B2BB-F227ACD711B1" ascii wide nocase
        $guid_1CC6E8A9_1875_430C_B2BB_F227ACD711B1_bin = { A9 E8 C6 1C 75 18 0C 43 B2 BB F2 27 AC D7 11 B1 }

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_1D1B59D9_10AF_40FE_BE99_578C09DB7A2A_str = "1D1B59D9-10AF-40FE-BE99-578C09DB7A2A" ascii wide nocase
        $guid_1D1B59D9_10AF_40FE_BE99_578C09DB7A2A_bin = { D9 59 1B 1D AF 10 FE 40 BE 99 57 8C 09 DB 7A 2A }

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_1DFC488D_E104_4F35_98DA_F23BF6D3F9DC_str = "1DFC488D-E104-4F35-98DA-F23BF6D3F9DC" ascii wide nocase
        $guid_1DFC488D_E104_4F35_98DA_F23BF6D3F9DC_bin = { 8D 48 FC 1D 04 E1 35 4F 98 DA F2 3B F6 D3 F9 DC }

        // Retrieve LAPS password from LDAP
        // https://github.com/swisskyrepo/SharpLAPS
        $guid_1E0986B4_4BF3_4CEA_A885_347B6D232D46_str = "1E0986B4-4BF3-4CEA-A885-347B6D232D46" ascii wide nocase
        $guid_1E0986B4_4BF3_4CEA_A885_347B6D232D46_bin = { B4 86 09 1E F3 4B EA 4C A8 85 34 7B 6D 23 2D 46 }

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_1e1f0cff_ff7a_406d_bd82_e53809a5e93a_str = "1e1f0cff-ff7a-406d-bd82-e53809a5e93a" ascii wide nocase
        $guid_1e1f0cff_ff7a_406d_bd82_e53809a5e93a_bin = { FF 0C 1F 1E 7A FF 6D 40 BD 82 E5 38 09 A5 E9 3A }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_1E2A1E78_ED0B_414B_A956_86232B1025BE_str = "1E2A1E78-ED0B-414B-A956-86232B1025BE" ascii wide nocase
        $guid_1E2A1E78_ED0B_414B_A956_86232B1025BE_bin = { 78 1E 2A 1E 0B ED 4B 41 A9 56 86 23 2B 10 25 BE }

        // A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // https://github.com/PhrozenIO/SharpFtpC2
        $guid_1E474090_96A7_433C_BFE6_0F8B45DECC42_str = "1E474090-96A7-433C-BFE6-0F8B45DECC42" ascii wide nocase
        $guid_1E474090_96A7_433C_BFE6_0F8B45DECC42_bin = { 90 40 47 1E A7 96 3C 43 BF E6 0F 8B 45 DE CC 42 }

        // Run Powershell without software restrictions.
        // https://github.com/iomoath/PowerShx
        $guid_1E70D62D_CC36_480F_82BB_E9593A759AF9_str = "1E70D62D-CC36-480F-82BB-E9593A759AF9" ascii wide nocase
        $guid_1E70D62D_CC36_480F_82BB_E9593A759AF9_bin = { 2D D6 70 1E 36 CC 0F 48 82 BB E9 59 3A 75 9A F9 }

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_1eb987e0_23a5_415e_9194_cd961314441b_str = "1eb987e0-23a5-415e-9194-cd961314441b" ascii wide nocase
        $guid_1eb987e0_23a5_415e_9194_cd961314441b_bin = { E0 87 B9 1E A5 23 5E 41 91 94 CD 96 13 14 44 1B }

        // Keylogging server and client that uses DNS tunneling/exfiltration to transmit keystrokes
        // https://github.com/Geeoon/DNS-Tunnel-Keylogger
        $guid_1fc325f3_c548_43db_a13f_8c460dda8381_str = "1fc325f3-c548-43db-a13f-8c460dda8381" ascii wide nocase
        $guid_1fc325f3_c548_43db_a13f_8c460dda8381_bin = { F3 25 C3 1F 48 C5 DB 43 A1 3F 8C 46 0D DA 83 81 }

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_1FDCAD33_E5D1_4D5F_ACD5_FA6F8661DFE5_str = "1FDCAD33-E5D1-4D5F-ACD5-FA6F8661DFE5" ascii wide nocase
        $guid_1FDCAD33_E5D1_4D5F_ACD5_FA6F8661DFE5_bin = { 33 AD DC 1F D1 E5 5F 4D AC D5 FA 6F 86 61 DF E5 }

        // A C# implementation of RDPThief to steal credentials from RDP
        // https://github.com/passthehashbrowns/SharpRDPThief
        $guid_20B3AA84_9CA7_43E5_B0CD_8DBA5091DF92_str = "20B3AA84-9CA7-43E5-B0CD-8DBA5091DF92" ascii wide nocase
        $guid_20B3AA84_9CA7_43E5_B0CD_8DBA5091DF92_bin = { 84 AA B3 20 A7 9C E5 43 B0 CD 8D BA 50 91 DF 92 }

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_210A3DB2_11E3_4BB4_BE7D_554935DCCA43_str = "210A3DB2-11E3-4BB4-BE7D-554935DCCA43" ascii wide nocase
        $guid_210A3DB2_11E3_4BB4_BE7D_554935DCCA43_bin = { B2 3D 0A 21 E3 11 B4 4B BE 7D 55 49 35 DC CA 43 }

        // Recovering NTLM hashes from Credential Guard
        // https://github.com/ly4k/PassTheChallenge
        $guid_2116E6C5_F609_4CA8_B1A1_E87B7BE770A4_str = "2116E6C5-F609-4CA8-B1A1-E87B7BE770A4" ascii wide nocase
        $guid_2116E6C5_F609_4CA8_B1A1_E87B7BE770A4_bin = { C5 E6 16 21 09 F6 A8 4C B1 A1 E8 7B 7B E7 70 A4 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_211A4598_B46E_4CD3_BA5A_1EC259D4DB5A_str = "211A4598-B46E-4CD3-BA5A-1EC259D4DB5A" ascii wide nocase
        $guid_211A4598_B46E_4CD3_BA5A_1EC259D4DB5A_bin = { 98 45 1A 21 6E B4 D3 4C BA 5A 1E C2 59 D4 DB 5A }

        // Adaptive DLL hijacking / dynamic export forwarding
        // https://github.com/monoxgas/Koppeling
        $guid_2150D252_AA17_45C2_8981_A6DCF7055CA6_str = "2150D252-AA17-45C2-8981-A6DCF7055CA6" ascii wide nocase
        $guid_2150D252_AA17_45C2_8981_A6DCF7055CA6_bin = { 52 D2 50 21 17 AA C2 45 89 81 A6 DC F7 05 5C A6 }

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_2164E6D9_6023_4932_A08F_7A5C15E2CA0B_str = "2164E6D9-6023-4932-A08F-7A5C15E2CA0B" ascii wide nocase
        $guid_2164E6D9_6023_4932_A08F_7A5C15E2CA0B_bin = { D9 E6 64 21 23 60 32 49 A0 8F 7A 5C 15 E2 CA 0B }

        // Creating a persistent service
        // https://github.com/uknowsec/CreateService
        $guid_22020898_6F0D_4D71_B14D_CB5897C5A6AA_str = "22020898-6F0D-4D71-B14D-CB5897C5A6AA" ascii wide nocase
        $guid_22020898_6F0D_4D71_B14D_CB5897C5A6AA_bin = { 98 08 02 22 0D 6F 71 4D B1 4D CB 58 97 C5 A6 AA }

        // Windows Privilege escalation POC exploitation for CVE-2024-49138
        // https://github.com/emdnaia/CVE-2024-49138-POC
        $guid_227c72ed_494a_4d29_9170_5e5994c12f5c_str = "227c72ed-494a-4d29-9170-5e5994c12f5c" ascii wide nocase
        $guid_227c72ed_494a_4d29_9170_5e5994c12f5c_bin = { ED 72 7C 22 4A 49 29 4D 91 70 5E 59 94 C1 2F 5C }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_2297A528_E866_4056_814A_D01C1C305A38_str = "2297A528-E866-4056-814A-D01C1C305A38" ascii wide nocase
        $guid_2297A528_E866_4056_814A_D01C1C305A38_bin = { 28 A5 97 22 66 E8 56 40 81 4A D0 1C 1C 30 5A 38 }

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_22A156EA_2623_45C7_8E50_E864D9FC44D3_str = "22A156EA-2623-45C7-8E50-E864D9FC44D3" ascii wide nocase
        $guid_22A156EA_2623_45C7_8E50_E864D9FC44D3_bin = { EA 56 A1 22 23 26 C7 45 8E 50 E8 64 D9 FC 44 D3 }

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_23975ac9_f51c_443a_8318_db006fd83100_str = "23975ac9-f51c-443a-8318-db006fd83100" ascii wide nocase
        $guid_23975ac9_f51c_443a_8318_db006fd83100_bin = { C9 5A 97 23 1C F5 3A 44 83 18 DB 00 6F D8 31 00 }

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_23A2E629_DC9D_46EA_8B5A_F1D60566EA09_str = "23A2E629-DC9D-46EA-8B5A-F1D60566EA09" ascii wide nocase
        $guid_23A2E629_DC9D_46EA_8B5A_F1D60566EA09_bin = { 29 E6 A2 23 9D DC EA 46 8B 5A F1 D6 05 66 EA 09 }

        // A tool that shows detailed information about named pipes in Windows
        // https://github.com/cyberark/PipeViewer
        $guid_2419CEDC_BF3A_4D8D_98F7_6403415BEEA4_str = "2419CEDC-BF3A-4D8D-98F7-6403415BEEA4" ascii wide nocase
        $guid_2419CEDC_BF3A_4D8D_98F7_6403415BEEA4_bin = { DC CE 19 24 3A BF 8D 4D 98 F7 64 03 41 5B EE A4 }

        // Perform DCSync operation
        // https://github.com/notsoshant/DCSyncer
        $guid_253e716a_ab96_4f87_88c7_052231ec2a12_str = "253e716a-ab96-4f87-88c7-052231ec2a12" ascii wide nocase
        $guid_253e716a_ab96_4f87_88c7_052231ec2a12_bin = { 6A 71 3E 25 96 AB 87 4F 88 C7 05 22 31 EC 2A 12 }

        // Another Windows Local Privilege Escalation from Service Account to System
        // https://github.com/antonioCoco/JuicyPotatoNG
        $guid_261f880e_4bee_428d_9f64_c29292002c19_str = "261f880e-4bee-428d-9f64-c29292002c19" ascii wide nocase
        $guid_261f880e_4bee_428d_9f64_c29292002c19_bin = { 0E 88 1F 26 EE 4B 8D 42 9F 64 C2 92 92 00 2C 19 }

        // XRulez is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
        // https://github.com/FSecureLABS/Xrulez
        $guid_2661F29C_69F5_4010_9198_A418C061DD7C_str = "2661F29C-69F5-4010-9198-A418C061DD7C" ascii wide nocase
        $guid_2661F29C_69F5_4010_9198_A418C061DD7C_bin = { 9C F2 61 26 F5 69 10 40 91 98 A4 18 C0 61 DD 7C }

        // A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // https://github.com/mdsecactivebreach/DragonCastle
        $guid_274F19EC_7CBA_4FC7_80E6_BB41C1FE6728_str = "274F19EC-7CBA-4FC7-80E6-BB41C1FE6728" ascii wide nocase
        $guid_274F19EC_7CBA_4FC7_80E6_BB41C1FE6728_bin = { EC 19 4F 27 BA 7C C7 4F 80 E6 BB 41 C1 FE 67 28 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_27CF1AE0_5FDE_4B31_A4DA_6FAD1D77351D_str = "27CF1AE0-5FDE-4B31-A4DA-6FAD1D77351D" ascii wide nocase
        $guid_27CF1AE0_5FDE_4B31_A4DA_6FAD1D77351D_bin = { E0 1A CF 27 DE 5F 31 4B A4 DA 6F AD 1D 77 35 1D }

        // Local Privilege Escalation from Admin to Kernel vulnerability on Windows 10 and Windows 11 operating systems with HVCI enabled.
        // https://github.com/hakaioffsec/CVE-2024-21338
        $guid_27E42E24_9F76_44E2_B1D6_82F68D5C4466_str = "27E42E24-9F76-44E2-B1D6-82F68D5C4466" ascii wide nocase
        $guid_27E42E24_9F76_44E2_B1D6_82F68D5C4466_bin = { 24 2E E4 27 76 9F E2 44 B1 D6 82 F6 8D 5C 44 66 }

        // Persistence by writing/reading shellcode from Event Log
        // https://github.com/improsec/SharpEventPersist
        $guid_27F85701_FD37_4D18_A107_20E914F8E779_str = "27F85701-FD37-4D18-A107-20E914F8E779" ascii wide nocase
        $guid_27F85701_FD37_4D18_A107_20E914F8E779_bin = { 01 57 F8 27 37 FD 18 4D A1 07 20 E9 14 F8 E7 79 }

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_28CF3837_FF58_463B_AF81_E6B0039DE55F_str = "28CF3837-FF58-463B-AF81-E6B0039DE55F" ascii wide nocase
        $guid_28CF3837_FF58_463B_AF81_E6B0039DE55F_bin = { 37 38 CF 28 58 FF 3B 46 AF 81 E6 B0 03 9D E5 5F }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_28F9E001_67E0_4200_B120_3021596689E9_str = "28F9E001-67E0-4200-B120-3021596689E9" ascii wide nocase
        $guid_28F9E001_67E0_4200_B120_3021596689E9_bin = { 01 E0 F9 28 E0 67 00 42 B1 20 30 21 59 66 89 E9 }

        // Tool for viewing NTDS.dit
        // https://github.com/trustedsec/DitExplorer
        $guid_29021B28_61F9_492D_BB51_7CA8889087E5_str = "29021B28-61F9-492D-BB51-7CA8889087E5" ascii wide nocase
        $guid_29021B28_61F9_492D_BB51_7CA8889087E5_bin = { 28 1B 02 29 F9 61 2D 49 BB 51 7C A8 88 90 87 E5 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_29390239_C06E_4F26_B5A3_594A08D8D30C_str = "29390239-C06E-4F26-B5A3-594A08D8D30C" ascii wide nocase
        $guid_29390239_C06E_4F26_B5A3_594A08D8D30C_bin = { 39 02 39 29 6E C0 26 4F B5 A3 59 4A 08 D8 D3 0C }

        // Github as C2
        // https://github.com/TheD1rkMtr/GithubC2
        $guid_29446C11_A1A5_47F6_B418_0D699C6C3339_str = "29446C11-A1A5-47F6-B418-0D699C6C3339" ascii wide nocase
        $guid_29446C11_A1A5_47F6_B418_0D699C6C3339_bin = { 11 6C 44 29 A5 A1 F6 47 B4 18 0D 69 9C 6C 33 39 }

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_2944dbfc_8a1e_4759_a8a2_e4568950601d_str = "2944dbfc-8a1e-4759-a8a2-e4568950601d" ascii wide nocase
        $guid_2944dbfc_8a1e_4759_a8a2_e4568950601d_bin = { FC DB 44 29 1E 8A 59 47 A8 A2 E4 56 89 50 60 1D }

        // Remote Command Executor: A OSS replacement for PsExec and RunAs
        // https://github.com/kavika13/RemCom
        $guid_29548EB7_5E44_21F9_5C82_15DDDC80449A_str = "29548EB7-5E44-21F9-5C82-15DDDC80449A" ascii wide nocase
        $guid_29548EB7_5E44_21F9_5C82_15DDDC80449A_bin = { B7 8E 54 29 44 5E F9 21 5C 82 15 DD DC 80 44 9A }

        // SharpStay - .NET Persistence
        // https://github.com/0xthirteen/SharpStay
        $guid_2963C954_7B1E_47F5_B4FA_2FC1F0D56AEA_str = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" ascii wide nocase
        $guid_2963C954_7B1E_47F5_B4FA_2FC1F0D56AEA_bin = { 54 C9 63 29 1E 7B F5 47 B4 FA 2F C1 F0 D5 6A EA }

        // Dump the memory of any PPL with a Userland exploit chain
        // https://github.com/itm4n/PPLmedic
        $guid_29CBBC24_363F_42D7_B018_5EF068BA8777_str = "29CBBC24-363F-42D7-B018-5EF068BA8777" ascii wide nocase
        $guid_29CBBC24_363F_42D7_B018_5EF068BA8777_bin = { 24 BC CB 29 3F 36 D7 42 B0 18 5E F0 68 BA 87 77 }

        // SharpSpray is a Windows domain password spraying tool written in .NET C#
        // https://github.com/iomoath/SharpSpray
        $guid_29CFAA16_9277_4EFB_9E91_A7D11225160B_str = "29CFAA16-9277-4EFB-9E91-A7D11225160B" ascii wide nocase
        $guid_29CFAA16_9277_4EFB_9E91_A7D11225160B_bin = { 16 AA CF 29 77 92 FB 4E 9E 91 A7 D1 12 25 16 0B }

        // RDP Wrapper Library used by malwares
        // https://github.com/stascorp/rdpwrap
        $guid_29E4E73B_EBA6_495B_A76C_FBB462196C64_str = "29E4E73B-EBA6-495B-A76C-FBB462196C64" ascii wide nocase
        $guid_29E4E73B_EBA6_495B_A76C_FBB462196C64_bin = { 3B E7 E4 29 A6 EB 5B 49 A7 6C FB B4 62 19 6C 64 }

        // ArtsOfGetSystem privesc tools
        // https://github.com/daem0nc0re/PrivFu/
        $guid_2AD3951D_DEA6_4CF7_88BE_4C73344AC9DA_str = "2AD3951D-DEA6-4CF7-88BE-4C73344AC9DA" ascii wide nocase
        $guid_2AD3951D_DEA6_4CF7_88BE_4C73344AC9DA_bin = { 1D 95 D3 2A A6 DE F7 4C 88 BE 4C 73 34 4A C9 DA }

        // DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // https://github.com/lypd0/DeadPotato
        $guid_2AE886C3_3272_40BE_8D3C_EBAEDE9E61E1_str = "2AE886C3-3272-40BE-8D3C-EBAEDE9E61E1" ascii wide nocase
        $guid_2AE886C3_3272_40BE_8D3C_EBAEDE9E61E1_bin = { C3 86 E8 2A 72 32 BE 40 8D 3C EB AE DE 9E 61 E1 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_2B47F84C_9CA3_47E9_9970_8AF8233A9F12_str = "2B47F84C-9CA3-47E9-9970-8AF8233A9F12" ascii wide nocase
        $guid_2B47F84C_9CA3_47E9_9970_8AF8233A9F12_bin = { 4C F8 47 2B A3 9C E9 47 99 70 8A F8 23 3A 9F 12 }

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_2B704D89_41B9_4051_A51C_36A82ACEBE10_str = "2B704D89-41B9-4051-A51C-36A82ACEBE10" ascii wide nocase
        $guid_2B704D89_41B9_4051_A51C_36A82ACEBE10_bin = { 89 4D 70 2B B9 41 51 40 A5 1C 36 A8 2A CE BE 10 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_2B914EE7_F206_4A83_B435_460D054315BB_str = "2B914EE7-F206-4A83-B435-460D054315BB" ascii wide nocase
        $guid_2B914EE7_F206_4A83_B435_460D054315BB_bin = { E7 4E 91 2B 06 F2 83 4A B4 35 46 0D 05 43 15 BB }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_2C059FE7_C868_4C6D_AFA0_D62BA3C1B2E1_str = "2C059FE7-C868-4C6D-AFA0-D62BA3C1B2E1" ascii wide nocase
        $guid_2C059FE7_C868_4C6D_AFA0_D62BA3C1B2E1_bin = { E7 9F 05 2C 68 C8 6D 4C AF A0 D6 2B A3 C1 B2 E1 }

        // MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // https://github.com/Xre0uS/MultiDump
        $guid_2C6D323A_B51F_47CB_AD37_972FD051D475_str = "2C6D323A-B51F-47CB-AD37-972FD051D475" ascii wide nocase
        $guid_2C6D323A_B51F_47CB_AD37_972FD051D475_bin = { 3A 32 6D 2C 1F B5 CB 47 AD 37 97 2F D0 51 D4 75 }

        // injection technique abusing windows fork API to evade EDRs
        // https://github.com/deepinstinct/Dirty-Vanity
        $guid_2C809982_78A1_4F1C_B0E8_C957C93B242F_str = "2C809982-78A1-4F1C-B0E8-C957C93B242F" ascii wide nocase
        $guid_2C809982_78A1_4F1C_B0E8_C957C93B242F_bin = { 82 99 80 2C A1 78 1C 4F B0 E8 C9 57 C9 3B 24 2F }

        // Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // https://github.com/deepinstinct/NoFilter
        $guid_2CFB9E9E_479D_4E23_9A8E_18C92E06B731_str = "2CFB9E9E-479D-4E23-9A8E-18C92E06B731" ascii wide nocase
        $guid_2CFB9E9E_479D_4E23_9A8E_18C92E06B731_bin = { 9E 9E FB 2C 9D 47 23 4E 9A 8E 18 C9 2E 06 B7 31 }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_2D6FDD44_39B1_4FF8_8AE0_60A6B0979F5F_str = "2D6FDD44-39B1-4FF8-8AE0-60A6B0979F5F" ascii wide nocase
        $guid_2D6FDD44_39B1_4FF8_8AE0_60A6B0979F5F_bin = { 44 DD 6F 2D B1 39 F8 4F 8A E0 60 A6 B0 97 9F 5F }

        // This PoC shows a technique that can be used to weaponize privileged file write vulnerabilities on Windows. It provides an alternative to the DiagHub DLL loading exploit 
        // https://github.com/itm4n/UsoDllLoader
        $guid_2D863D7A_A369_419C_B4B3_54BDB88B5816_str = "2D863D7A-A369-419C-B4B3-54BDB88B5816" ascii wide nocase
        $guid_2D863D7A_A369_419C_B4B3_54BDB88B5816_bin = { 7A 3D 86 2D 69 A3 9C 41 B4 B3 54 BD B8 8B 58 16 }

        // Hotkey-based keylogger for Windows
        // https://github.com/yo-yo-yo-jbo/hotkeyz
        $guid_2deff2ca_c313_4d85_aeee_414bac32e7ae_str = "2deff2ca-c313-4d85-aeee-414bac32e7ae" ascii wide nocase
        $guid_2deff2ca_c313_4d85_aeee_414bac32e7ae_bin = { CA F2 EF 2D 13 C3 85 4D AE EE 41 4B AC 32 E7 AE }

        // Windows injection of x86/x64 DLL and Shellcode
        // https://github.com/Joe1sn/S-inject
        $guid_2E98B8D4_7A26_4F04_A95D_2051B0AB884C_str = "2E98B8D4-7A26-4F04-A95D-2051B0AB884C" ascii wide nocase
        $guid_2E98B8D4_7A26_4F04_A95D_2051B0AB884C_bin = { D4 B8 98 2E 26 7A 04 4F A9 5D 20 51 B0 AB 88 4C }

        // p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET). It has a lot of offensive PowerShell modules and binaries included to make the process of Post Exploitation easier. What we tried was to build an ?all in one? Post Exploitation tool which we could use to bypass all mitigations solutions (or at least some off). and that has all relevant tooling included. You can use it to perform modern attacks within Active Directory environments and create awareness within your Blue team so they can build the right defense strategies.
        // https://github.com/Cn33liz/p0wnedShell
        $guid_2E9B1462_F47C_48CA_9D85_004493892381_str = "2E9B1462-F47C-48CA-9D85-004493892381" ascii wide nocase
        $guid_2E9B1462_F47C_48CA_9D85_004493892381_bin = { 62 14 9B 2E 7C F4 CA 48 9D 85 00 44 93 89 23 81 }

        // SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // https://github.com/GhostPack/SharpDPAPI
        $guid_2F00A05B_263D_4FCC_846B_DA82BD684603_str = "2F00A05B-263D-4FCC-846B-DA82BD684603" ascii wide nocase
        $guid_2F00A05B_263D_4FCC_846B_DA82BD684603_bin = { 5B A0 00 2F 3D 26 CC 4F 84 6B DA 82 BD 68 46 03 }

        // Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // https://github.com/Imanfeng/Telemetry
        $guid_2f00a05b_263d_4fcc_846b_da82bd684603_str = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii wide nocase
        $guid_2f00a05b_263d_4fcc_846b_da82bd684603_bin = { 5B A0 00 2F 3D 26 CC 4F 84 6B DA 82 BD 68 46 03 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_2F8E74D2_3474_408C_9469_A4E3C97B7BBF_str = "2F8E74D2-3474-408C-9469-A4E3C97B7BBF" ascii wide nocase
        $guid_2F8E74D2_3474_408C_9469_A4E3C97B7BBF_bin = { D2 74 8E 2F 74 34 8C 40 94 69 A4 E3 C9 7B 7B BF }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_2FB94059_2D49_4EEA_AAF8_7E89E249644B_str = "2FB94059-2D49-4EEA-AAF8-7E89E249644B" ascii wide nocase
        $guid_2FB94059_2D49_4EEA_AAF8_7E89E249644B_bin = { 59 40 B9 2F 49 2D EA 4E AA F8 7E 89 E2 49 64 4B }

        // Crack any Microsoft Windows users password without any privilege (Guest account included)
        // https://github.com/PhrozenIO/win-brute-logon
        $guid_2FE6C1D0_0538_48DB_B4FA_55F0296A5150_str = "2FE6C1D0-0538-48DB-B4FA-55F0296A5150" ascii wide nocase
        $guid_2FE6C1D0_0538_48DB_B4FA_55F0296A5150_bin = { D0 C1 E6 2F 38 05 DB 48 B4 FA 55 F0 29 6A 51 50 }

        // PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // https://github.com/poweradminllc/PAExec
        $guid_2FEB96F5_08E6_48A3_B306_794277650A08_str = "2FEB96F5-08E6-48A3-B306-794277650A08" ascii wide nocase
        $guid_2FEB96F5_08E6_48A3_B306_794277650A08_bin = { F5 96 EB 2F E6 08 A3 48 B3 06 79 42 77 65 0A 08 }

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_304D5A8A_EF98_4E21_8F4D_91E66E0BECAC_str = "304D5A8A-EF98-4E21-8F4D-91E66E0BECAC" ascii wide nocase
        $guid_304D5A8A_EF98_4E21_8F4D_91E66E0BECAC_bin = { 8A 5A 4D 30 98 EF 21 4E 8F 4D 91 E6 6E 0B EC AC }

        // Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // https://github.com/outflanknl/Dumpert
        $guid_307088B9_2992_4DE7_A57D_9E657B1CE546_str = "307088B9-2992-4DE7-A57D-9E657B1CE546" ascii wide nocase
        $guid_307088B9_2992_4DE7_A57D_9E657B1CE546_bin = { B9 88 70 30 92 29 E7 4D A5 7D 9E 65 7B 1C E5 46 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_30B8883F_A0A2_4256_ADCF_A790525D3696_str = "30B8883F-A0A2-4256-ADCF-A790525D3696" ascii wide nocase
        $guid_30B8883F_A0A2_4256_ADCF_A790525D3696_bin = { 3F 88 B8 30 A2 A0 56 42 AD CF A7 90 52 5D 36 96 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_310FC5BE_6F5E_479C_A246_6093A39296C0_str = "310FC5BE-6F5E-479C-A246-6093A39296C0" ascii wide nocase
        $guid_310FC5BE_6F5E_479C_A246_6093A39296C0_bin = { BE C5 0F 31 5E 6F 9C 47 A2 46 60 93 A3 92 96 C0 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_315C301F_E392_4F7D_9108_8E621C11D662_str = "315C301F-E392-4F7D-9108-8E621C11D662" ascii wide nocase
        $guid_315C301F_E392_4F7D_9108_8E621C11D662_bin = { 1F 30 5C 31 92 E3 7D 4F 91 08 8E 62 1C 11 D6 62 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_32223BE8_3E78_489C_92ED_7900B26DFF43_str = "32223BE8-3E78-489C-92ED-7900B26DFF43" ascii wide nocase
        $guid_32223BE8_3E78_489C_92ED_7900B26DFF43_bin = { E8 3B 22 32 78 3E 9C 48 92 ED 79 00 B2 6D FF 43 }

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_326D0AB1_CF2F_4A9B_B612_04B62D4EBA89_str = "326D0AB1-CF2F-4A9B-B612-04B62D4EBA89" ascii wide nocase
        $guid_326D0AB1_CF2F_4A9B_B612_04B62D4EBA89_bin = { B1 0A 6D 32 2F CF 9B 4A B6 12 04 B6 2D 4E BA 89 }

        // enabling Recall in Windows 11 version 24H2 on unsupported devices
        // https://github.com/thebookisclosed/AmperageKit
        $guid_327F3F26_182F_4E58_ABEA_A0CEDBCA0FCD_str = "327F3F26-182F-4E58-ABEA-A0CEDBCA0FCD" ascii wide nocase
        $guid_327F3F26_182F_4E58_ABEA_A0CEDBCA0FCD_bin = { 26 3F 7F 32 2F 18 58 4E AB EA A0 CE DB CA 0F CD }

        // Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // https://github.com/quasar/Quasar
        $guid_32A2A734_7429_47E6_A362_E344A19C0D85_str = "32A2A734-7429-47E6-A362-E344A19C0D85" ascii wide nocase
        $guid_32A2A734_7429_47E6_A362_E344A19C0D85_bin = { 34 A7 A2 32 29 74 E6 47 A3 62 E3 44 A1 9C 0D 85 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_32CE1CB1_B7D9_416F_8EFE_6A0055867537_str = "32CE1CB1-B7D9-416F-8EFE-6A0055867537" ascii wide nocase
        $guid_32CE1CB1_B7D9_416F_8EFE_6A0055867537_bin = { B1 1C CE 32 D9 B7 6F 41 8E FE 6A 00 55 86 75 37 }

        // enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // https://github.com/FalconForceTeam/SOAPHound
        $guid_33571B09_4E94_43CB_ABDC_0226D769E701_str = "33571B09-4E94-43CB-ABDC-0226D769E701" ascii wide nocase
        $guid_33571B09_4E94_43CB_ABDC_0226D769E701_bin = { 09 1B 57 33 94 4E CB 43 AB DC 02 26 D7 69 E7 01 }

        // CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // https://github.com/Prepouce/CoercedPotato
        $guid_337ED7BE_969A_40C4_A356_BE99561F4633_str = "337ED7BE-969A-40C4-A356-BE99561F4633" ascii wide nocase
        $guid_337ED7BE_969A_40C4_A356_BE99561F4633_bin = { BE D7 7E 33 9A 96 C4 40 A3 56 BE 99 56 1F 46 33 }

        // RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // https://github.com/tastypepperoni/RunAsWinTcb
        $guid_33BF8AA2_18DE_4ED9_9613_A4118CBFC32A_str = "33BF8AA2-18DE-4ED9-9613-A4118CBFC32A" ascii wide nocase
        $guid_33BF8AA2_18DE_4ED9_9613_A4118CBFC32A_bin = { A2 8A BF 33 DE 18 D9 4E 96 13 A4 11 8C BF C3 2A }

        // RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // https://github.com/S12cybersecurity/RDPCredentialStealer
        $guid_33d0f399_f79a_44a2_a487_21fce657be35_str = "33d0f399-f79a-44a2-a487-21fce657be35" ascii wide nocase
        $guid_33d0f399_f79a_44a2_a487_21fce657be35_bin = { 99 F3 D0 33 9A F7 A2 44 A4 87 21 FC E6 57 BE 35 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3504F678_95FA_4DB2_8437_31A927CABC16_str = "3504F678-95FA-4DB2-8437-31A927CABC16" ascii wide nocase
        $guid_3504F678_95FA_4DB2_8437_31A927CABC16_bin = { 78 F6 04 35 FA 95 B2 4D 84 37 31 A9 27 CA BC 16 }

        // SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $guid_360F9CE5_D927_46B9_8416_4118D0B68360_str = "360F9CE5-D927-46B9-8416-4118D0B68360" ascii wide nocase
        $guid_360F9CE5_D927_46B9_8416_4118D0B68360_bin = { E5 9C 0F 36 27 D9 B9 46 84 16 41 18 D0 B6 83 60 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_363A6DE4_59D9_451B_A4FD_1FE763970E1E_str = "363A6DE4-59D9-451B-A4FD-1FE763970E1E" ascii wide nocase
        $guid_363A6DE4_59D9_451B_A4FD_1FE763970E1E_bin = { E4 6D 3A 36 D9 59 1B 45 A4 FD 1F E7 63 97 0E 1E }

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_36AB45D2_F886_4803_AA7E_6FD5520458FC_str = "36AB45D2-F886-4803-AA7E-6FD5520458FC" ascii wide nocase
        $guid_36AB45D2_F886_4803_AA7E_6FD5520458FC_bin = { D2 45 AB 36 86 F8 03 48 AA 7E 6F D5 52 04 58 FC }

        // Keylogger written in C#
        // https://github.com/djhohnstein/SharpLogger
        $guid_36E00152_E073_4DA8_AA0C_375B6DD680C4_str = "36E00152-E073-4DA8-AA0C-375B6DD680C4" ascii wide nocase
        $guid_36E00152_E073_4DA8_AA0C_375B6DD680C4_bin = { 52 01 E0 36 73 E0 A8 4D AA 0C 37 5B 6D D6 80 C4 }

        // Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // https://github.com/p3nt4/PowerShdll
        $guid_36EBF9AA_2F37_4F1D_A2F1_F2A45DEEAF21_str = "36EBF9AA-2F37-4F1D-A2F1-F2A45DEEAF21" ascii wide nocase
        $guid_36EBF9AA_2F37_4F1D_A2F1_F2A45DEEAF21_bin = { AA F9 EB 36 37 2F 1D 4F A2 F1 F2 A4 5D EE AF 21 }

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_36F9C306_5F45_4946_A259_610C05BD90DF_str = "36F9C306-5F45-4946-A259-610C05BD90DF" ascii wide nocase
        $guid_36F9C306_5F45_4946_A259_610C05BD90DF_bin = { 06 C3 F9 36 45 5F 46 49 A2 59 61 0C 05 BD 90 DF }

        // DebugAmsi is another way to bypass AMSI through the Windows process debugger mechanism.
        // https://github.com/MzHmO/DebugAmsi
        $guid_375D8508_F60D_4E24_9DF6_1E591D2FA474_str = "375D8508-F60D-4E24-9DF6-1E591D2FA474" ascii wide nocase
        $guid_375D8508_F60D_4E24_9DF6_1E591D2FA474_bin = { 08 85 5D 37 0D F6 24 4E 9D F6 1E 59 1D 2F A4 74 }

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_3787435B_8352_4BD8_A1C6_E5A1B73921F4_str = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" ascii wide nocase
        $guid_3787435B_8352_4BD8_A1C6_E5A1B73921F4_bin = { 5B 43 87 37 52 83 D8 4B A1 C6 E5 A1 B7 39 21 F4 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_378FC1AA_37BD_4C61_B5DE_4E45C2CDB8C9_str = "378FC1AA-37BD-4C61-B5DE-4E45C2CDB8C9" ascii wide nocase
        $guid_378FC1AA_37BD_4C61_B5DE_4E45C2CDB8C9_bin = { AA C1 8F 37 BD 37 61 4C B5 DE 4E 45 C2 CD B8 C9 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_37E20BAF_3577_4CD9_BB39_18675854E255_str = "37E20BAF-3577-4CD9-BB39-18675854E255" ascii wide nocase
        $guid_37E20BAF_3577_4CD9_BB39_18675854E255_bin = { AF 0B E2 37 77 35 D9 4C BB 39 18 67 58 54 E2 55 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_382B6332_4A57_458D_96EB_B312688A7604_str = "382B6332-4A57-458D-96EB-B312688A7604" ascii wide nocase
        $guid_382B6332_4A57_458D_96EB_B312688A7604_bin = { 32 63 2B 38 57 4A 8D 45 96 EB B3 12 68 8A 76 04 }

        // Command and control server - multi-person collaborative penetration testing graphical framework
        // https://github.com/INotGreen/Xiebro-Plugins
        $guid_38AF011B_95F8_4F42_B4B9_B1AEE328A583_str = "38AF011B-95F8-4F42-B4B9-B1AEE328A583" ascii wide nocase
        $guid_38AF011B_95F8_4F42_B4B9_B1AEE328A583_bin = { 1B 01 AF 38 F8 95 42 4F B4 B9 B1 AE E3 28 A5 83 }

        // AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // https://github.com/AutoHotkey/AutoHotkey
        $guid_39037993_9571_4DF2_8E39_CD2909043574_str = "39037993-9571-4DF2-8E39-CD2909043574" ascii wide nocase
        $guid_39037993_9571_4DF2_8E39_CD2909043574_bin = { 93 79 03 39 71 95 F2 4D 8E 39 CD 29 09 04 35 74 }

        // EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // https://github.com/wavestone-cdt/EDRSandblast
        $guid_3A2FCB56_01A3_41B3_BDAA_B25F45784B23_str = "3A2FCB56-01A3-41B3-BDAA-B25F45784B23" ascii wide nocase
        $guid_3A2FCB56_01A3_41B3_BDAA_B25F45784B23_bin = { 56 CB 2F 3A A3 01 B3 41 BD AA B2 5F 45 78 4B 23 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3ADB8BB1_AE14_49DA_A7E1_1C0D9BEB76E9_str = "3ADB8BB1-AE14-49DA-A7E1-1C0D9BEB76E9" ascii wide nocase
        $guid_3ADB8BB1_AE14_49DA_A7E1_1C0D9BEB76E9_bin = { B1 8B DB 3A 14 AE DA 49 A7 E1 1C 0D 9B EB 76 E9 }

        // acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // https://github.com/decoder-it/KrbRelay-SMBServer
        $guid_3B47EEBC_0D33_4E0B_BAB5_782D2D3680AF_str = "3B47EEBC-0D33-4E0B-BAB5-782D2D3680AF" ascii wide nocase
        $guid_3B47EEBC_0D33_4E0B_BAB5_782D2D3680AF_bin = { BC EE 47 3B 33 0D 0B 4E BA B5 78 2D 2D 36 80 AF }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3B85D7A9_6BD0_4CD8_9009_36554EF24D32_str = "3B85D7A9-6BD0-4CD8-9009-36554EF24D32" ascii wide nocase
        $guid_3B85D7A9_6BD0_4CD8_9009_36554EF24D32_bin = { A9 D7 85 3B D0 6B D8 4C 90 09 36 55 4E F2 4D 32 }

        // DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // https://github.com/outflanknl/NetshHelperBeacon
        $guid_3BB0CD58_487C_4FEC_8001_607599477158_str = "3BB0CD58-487C-4FEC-8001-607599477158" ascii wide nocase
        $guid_3BB0CD58_487C_4FEC_8001_607599477158_bin = { 58 CD B0 3B 7C 48 EC 4F 80 01 60 75 99 47 71 58 }

        // Modular C# framework to exfiltrate loot over secure and trusted channels.
        // https://github.com/Flangvik/SharpExfiltrate
        $guid_3bb553cd_0a48_402d_9812_8daff60ac628_str = "3bb553cd-0a48-402d-9812-8daff60ac628" ascii wide nocase
        $guid_3bb553cd_0a48_402d_9812_8daff60ac628_bin = { CD 53 B5 3B 48 0A 2D 40 98 12 8D AF F6 0A C6 28 }

        // Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // https://github.com/hfiref0x/UACME
        $guid_3BEF8A16_981F_4C65_8AE7_C612B46BE446_str = "3BEF8A16-981F-4C65-8AE7-C612B46BE446" ascii wide nocase
        $guid_3BEF8A16_981F_4C65_8AE7_C612B46BE446_bin = { 16 8A EF 3B 1F 98 65 4C 8A E7 C6 12 B4 6B E4 46 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_3C0E89F1_1D3D_4651_9A44_FCCABB340E02_str = "3C0E89F1-1D3D-4651-9A44-FCCABB340E02" ascii wide nocase
        $guid_3C0E89F1_1D3D_4651_9A44_FCCABB340E02_bin = { F1 89 0E 3C 3D 1D 51 46 9A 44 FC CA BB 34 0E 02 }

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_3C21F82B_B958_457A_82BB_B8A795316D3D_str = "3C21F82B-B958-457A-82BB-B8A795316D3D" ascii wide nocase
        $guid_3C21F82B_B958_457A_82BB_B8A795316D3D_bin = { 2B F8 21 3C 58 B9 7A 45 82 BB B8 A7 95 31 6D 3D }

        // A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // https://github.com/TheD1rkMtr/TakeMyRDP
        $guid_3C601672_7389_42B2_B5C9_059846E1DA88_str = "3C601672-7389-42B2-B5C9-059846E1DA88" ascii wide nocase
        $guid_3C601672_7389_42B2_B5C9_059846E1DA88_bin = { 72 16 60 3C 89 73 B2 42 B5 C9 05 98 46 E1 DA 88 }

        // Enable or Disable TokenPrivilege(s)
        // https://github.com/xvt-void/EnableAllTokenPrivs
        $guid_3C8AA457_3659_4CDD_A685_66F7ED10DC4F_str = "3C8AA457-3659-4CDD-A685-66F7ED10DC4F" ascii wide nocase
        $guid_3C8AA457_3659_4CDD_A685_66F7ED10DC4F_bin = { 57 A4 8A 3C 59 36 DD 4C A6 85 66 F7 ED 10 DC 4F }

        // disable windows defender. (through the WSC api)
        // https://github.com/es3n1n/no-defender
        $guid_3CFB521D_40ED_4891_8B6C_ED0644A237C1_str = "3CFB521D-40ED-4891-8B6C-ED0644A237C1" ascii wide nocase
        $guid_3CFB521D_40ED_4891_8B6C_ED0644A237C1_bin = { 1D 52 FB 3C ED 40 91 48 8B 6C ED 06 44 A2 37 C1 }

        // OPSEC safe Kerberoasting in C#
        // https://github.com/Luct0r/KerberOPSEC
        $guid_3D111394_E7F7_40B7_91CB_D24374DB739A_str = "3D111394-E7F7-40B7-91CB-D24374DB739A" ascii wide nocase
        $guid_3D111394_E7F7_40B7_91CB_D24374DB739A_bin = { 94 13 11 3D F7 E7 B7 40 91 CB D2 43 74 DB 73 9A }

        // .NET assembly to interact with services. (included in powershell empire)
        // https://github.com/djhohnstein/SharpSC
        $guid_3D9D679D_6052_4C5E_BD91_2BC3DED09D0A_str = "3D9D679D-6052-4C5E-BD91-2BC3DED09D0A" ascii wide nocase
        $guid_3D9D679D_6052_4C5E_BD91_2BC3DED09D0A_bin = { 9D 67 9D 3D 52 60 5E 4C BD 91 2B C3 DE D0 9D 0A }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3EAB01B5_9B49_48D8_BFA1_5493B26CCB71_str = "3EAB01B5-9B49-48D8-BFA1-5493B26CCB71" ascii wide nocase
        $guid_3EAB01B5_9B49_48D8_BFA1_5493B26CCB71_bin = { B5 01 AB 3E 49 9B D8 48 BF A1 54 93 B2 6C CB 71 }

        // Identifies the bytes that Microsoft Defender / AMSI Consumer flags on
        // https://github.com/rasta-mouse/ThreatCheck
        $guid_3EC9B9A8_0AFE_44A7_8B95_7F60E750F042_str = "3EC9B9A8-0AFE-44A7-8B95-7F60E750F042" ascii wide nocase
        $guid_3EC9B9A8_0AFE_44A7_8B95_7F60E750F042_bin = { A8 B9 C9 3E FE 0A A7 44 8B 95 7F 60 E7 50 F0 42 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_3F0C3D9A_CFB8_4DB5_8419_1C28CBC8621D_str = "3F0C3D9A-CFB8-4DB5-8419-1C28CBC8621D" ascii wide nocase
        $guid_3F0C3D9A_CFB8_4DB5_8419_1C28CBC8621D_bin = { 9A 3D 0C 3F B8 CF B5 4D 84 19 1C 28 CB C8 62 1D }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_3F5558BD_7B94_4CB0_A46C_A7252B5BCA17_str = "3F5558BD-7B94-4CB0-A46C-A7252B5BCA17" ascii wide nocase
        $guid_3F5558BD_7B94_4CB0_A46C_A7252B5BCA17_bin = { BD 58 55 3F 94 7B B0 4C A4 6C A7 25 2B 5B CA 17 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_3FBBC3DD_39D9_4D8C_AF73_EDC3D2849DEB_str = "3FBBC3DD-39D9-4D8C-AF73-EDC3D2849DEB" ascii wide nocase
        $guid_3FBBC3DD_39D9_4D8C_AF73_EDC3D2849DEB_bin = { DD C3 BB 3F D9 39 8C 4D AF 73 ED C3 D2 84 9D EB }

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_3FCA8012_3BAD_41E4_91F4_534AA9A44F96_str = "3FCA8012-3BAD-41E4-91F4-534AA9A44F96" ascii wide nocase
        $guid_3FCA8012_3BAD_41E4_91F4_534AA9A44F96_bin = { 12 80 CA 3F AD 3B E4 41 91 F4 53 4A A9 A4 4F 96 }

        // Remote Shellcode Injector
        // https://github.com/florylsk/NtRemoteLoad
        $guid_40B05F26_6A2F_40BC_88DE_F40D4BC77FB0_str = "40B05F26-6A2F-40BC-88DE-F40D4BC77FB0" ascii wide nocase
        $guid_40B05F26_6A2F_40BC_88DE_F40D4BC77FB0_bin = { 26 5F B0 40 2F 6A BC 40 88 DE F4 0D 4B C7 7F B0 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_40C64006_EE9C_4EC8_A378_B8499142C071_str = "40C64006-EE9C-4EC8-A378-B8499142C071" ascii wide nocase
        $guid_40C64006_EE9C_4EC8_A378_B8499142C071_bin = { 06 40 C6 40 9C EE C8 4E A3 78 B8 49 91 42 C0 71 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_40C6A1BB_69AA_4869_81EE_41917D0B009A_str = "40C6A1BB-69AA-4869-81EE-41917D0B009A" ascii wide nocase
        $guid_40C6A1BB_69AA_4869_81EE_41917D0B009A_bin = { BB A1 C6 40 AA 69 69 48 81 EE 41 91 7D 0B 00 9A }

        // Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // https://github.com/unkvolism/Fuck-Etw
        $guid_40E7714F_460D_4CA6_9A5A_FB32C6769BE4_str = "40E7714F-460D-4CA6-9A5A-FB32C6769BE4" ascii wide nocase
        $guid_40E7714F_460D_4CA6_9A5A_FB32C6769BE4_bin = { 4F 71 E7 40 0D 46 A6 4C 9A 5A FB 32 C6 76 9B E4 }

        // Tool to execute token assigned process
        // https://github.com/daem0nc0re/PrivFu
        $guid_410D25CC_A75E_4B65_8D24_05FA4D8AE0B9_str = "410D25CC-A75E-4B65-8D24-05FA4D8AE0B9" ascii wide nocase
        $guid_410D25CC_A75E_4B65_8D24_05FA4D8AE0B9_bin = { CC 25 0D 41 5E A7 65 4B 8D 24 05 FA 4D 8A E0 B9 }

        // coercing machine authentication but specific for ADCS server
        // https://github.com/decoder-it/ADCSCoercePotato
        $guid_4164003E_BA47_4A95_8586_D5AAC399C050_str = "4164003E-BA47-4A95-8586-D5AAC399C050" ascii wide nocase
        $guid_4164003E_BA47_4A95_8586_D5AAC399C050_bin = { 3E 00 64 41 47 BA 95 4A 85 86 D5 AA C3 99 C0 50 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_416656DC_D499_498B_8ACF_6502A13EFC9E_str = "416656DC-D499-498B-8ACF-6502A13EFC9E" ascii wide nocase
        $guid_416656DC_D499_498B_8ACF_6502A13EFC9E_bin = { DC 56 66 41 99 D4 8B 49 8A CF 65 02 A1 3E FC 9E }

        // disable windows defender. (through the WSC api)
        // https://github.com/es3n1n/no-defender
        $guid_4193DE42_C103_45FF_A04D_0AD64616BC59_str = "4193DE42-C103-45FF-A04D-0AD64616BC59" ascii wide nocase
        $guid_4193DE42_C103_45FF_A04D_0AD64616BC59_bin = { 42 DE 93 41 03 C1 FF 45 A0 4D 0A D6 46 16 BC 59 }

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD753_str = "41A90A6A-F9ED-4A2F-8448-D544EC1FD753" ascii wide nocase
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD753_bin = { 6A 0A A9 41 ED F9 2F 4A 84 48 D5 44 EC 1F D7 53 }

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD754_str = "41A90A6A-F9ED-4A2F-8448-D544EC1FD754" ascii wide nocase
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD754_bin = { 6A 0A A9 41 ED F9 2F 4A 84 48 D5 44 EC 1F D7 54 }

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD755_str = "41A90A6A-F9ED-4A2F-8448-D544EC1FD755" ascii wide nocase
        $guid_41A90A6A_F9ED_4A2F_8448_D544EC1FD755_bin = { 6A 0A A9 41 ED F9 2F 4A 84 48 D5 44 EC 1F D7 55 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_424B81BE_2FAC_419F_B4BC_00CCBE38491F_str = "424B81BE-2FAC-419F-B4BC-00CCBE38491F" ascii wide nocase
        $guid_424B81BE_2FAC_419F_B4BC_00CCBE38491F_bin = { BE 81 4B 42 AC 2F 9F 41 B4 BC 00 CC BE 38 49 1F }

        // SharpElevator is a C# implementation of Elevator for UAC bypass
        // https://github.com/eladshamir/SharpElevator
        $guid_42BDEFC0_0BAE_43DF_97BB_C805ABFBD078_str = "42BDEFC0-0BAE-43DF-97BB-C805ABFBD078" ascii wide nocase
        $guid_42BDEFC0_0BAE_43DF_97BB_C805ABFBD078_bin = { C0 EF BD 42 AE 0B DF 43 97 BB C8 05 AB FB D0 78 }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_4349B8A8_F17B_44D5_AE4D_21BE9C9D1573_str = "4349B8A8-F17B-44D5-AE4D-21BE9C9D1573" ascii wide nocase
        $guid_4349B8A8_F17B_44D5_AE4D_21BE9C9D1573_bin = { A8 B8 49 43 7B F1 D5 44 AE 4D 21 BE 9C 9D 15 73 }

        // An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // https://github.com/eladshamir/BadWindowsService
        $guid_43A031B0_E040_4D5E_B477_02651F5E3D62_str = "43A031B0-E040-4D5E-B477-02651F5E3D62" ascii wide nocase
        $guid_43A031B0_E040_4D5E_B477_02651F5E3D62_bin = { B0 31 A0 43 40 E0 5E 4D B4 77 02 65 1F 5E 3D 62 }

        // interactive remote shell access via named pipes and the SMB protocol.
        // https://github.com/DarkCoderSc/SharpShellPipe
        $guid_43BB3C30_39D7_4B6B_972E_1E2B94D4D53A_str = "43BB3C30-39D7-4B6B-972E-1E2B94D4D53A" ascii wide nocase
        $guid_43BB3C30_39D7_4B6B_972E_1E2B94D4D53A_bin = { 30 3C BB 43 D7 39 6B 4B 97 2E 1E 2B 94 D4 D5 3A }

        // Tool to create hidden registry keys
        // https://github.com/outflanknl/SharpHide
        $guid_443D8CBF_899C_4C22_B4F6_B7AC202D4E37_str = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" ascii wide nocase
        $guid_443D8CBF_899C_4C22_B4F6_B7AC202D4E37_bin = { BF 8C 3D 44 9C 89 22 4C B4 F6 B7 AC 20 2D 4E 37 }

        // Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // https://github.com/daem0nc0re/PrivFu
        $guid_449CE476_7B27_47F5_B09C_570788A2F261_str = "449CE476-7B27-47F5-B09C-570788A2F261" ascii wide nocase
        $guid_449CE476_7B27_47F5_B09C_570788A2F261_bin = { 76 E4 9C 44 27 7B F5 47 B0 9C 57 07 88 A2 F2 61 }

        // A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // https://github.com/PhrozenIO/SharpFtpC2
        $guid_44D0366D_742F_4E0B_A67D_3B1044A66EA7_str = "44D0366D-742F-4E0B-A67D-3B1044A66EA7" ascii wide nocase
        $guid_44D0366D_742F_4E0B_A67D_3B1044A66EA7_bin = { 6D 36 D0 44 2F 74 0B 4E A6 7D 3B 10 44 A6 6E A7 }

        // Shoggoth: Asmjit Based Polymorphic Encryptor
        // https://github.com/frkngksl/Shoggoth
        $guid_44D5BE95_F34D_4CC5_846F_C7758943B8FA_str = "44D5BE95-F34D-4CC5-846F-C7758943B8FA" ascii wide nocase
        $guid_44D5BE95_F34D_4CC5_846F_C7758943B8FA_bin = { 95 BE D5 44 4D F3 C5 4C 84 6F C7 75 89 43 B8 FA }

        // A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // https://github.com/SafeBreach-Labs/PoolParty
        $guid_45D59D79_EF51_4A93_AAFA_2879FFC3A62C_str = "45D59D79-EF51-4A93-AAFA-2879FFC3A62C" ascii wide nocase
        $guid_45D59D79_EF51_4A93_AAFA_2879FFC3A62C_bin = { 79 9D D5 45 51 EF 93 4A AA FA 28 79 FF C3 A6 2C }

        // Tunnel TCP connections through a file
        // https://github.com/fiddyschmitt/File-Tunnel
        $guid_461F72D2_6BDC_4D0E_82EE_59A811AB4844_str = "461F72D2-6BDC-4D0E-82EE-59A811AB4844" ascii wide nocase
        $guid_461F72D2_6BDC_4D0E_82EE_59A811AB4844_bin = { D2 72 1F 46 DC 6B 0E 4D 82 EE 59 A8 11 AB 48 44 }

        // GPO attack vectors through NTLM relaying
        // https://github.com/synacktiv/GPOddity
        $guid_46993522_7D77_4B59_9B77_F82082DE9D81_str = "46993522-7D77-4B59-9B77-F82082DE9D81" ascii wide nocase
        $guid_46993522_7D77_4B59_9B77_F82082DE9D81_bin = { 22 35 99 46 77 7D 59 4B 9B 77 F8 20 82 DE 9D 81 }

        // dump LSASS memory
        // https://github.com/Offensive-Panda/ShadowDumper
        $guid_46D3E566_0EBA_4BD9_925E_84F4CB9EE7BC_str = "46D3E566-0EBA-4BD9-925E-84F4CB9EE7BC" ascii wide nocase
        $guid_46D3E566_0EBA_4BD9_925E_84F4CB9EE7BC_bin = { 66 E5 D3 46 BA 0E D9 4B 92 5E 84 F4 CB 9E E7 BC }

        // An App Domain Manager Injection DLL PoC
        // https://github.com/ipSlav/DirtyCLR
        $guid_46EB7B83_3404_4DFC_94CC_704B02D11464_str = "46EB7B83-3404-4DFC-94CC-704B02D11464" ascii wide nocase
        $guid_46EB7B83_3404_4DFC_94CC_704B02D11464_bin = { 83 7B EB 46 04 34 FC 4D 94 CC 70 4B 02 D1 14 64 }

        // A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $guid_474B99B7_66C4_4AC2_8AD3_065DD13DDDFF_str = "474B99B7-66C4-4AC2-8AD3-065DD13DDDFF" ascii wide nocase
        $guid_474B99B7_66C4_4AC2_8AD3_065DD13DDDFF_bin = { B7 99 4B 47 C4 66 C2 4A 8A D3 06 5D D1 3D DD FF }

        // A quick scanner for the CVE-2019-0708 "BlueKeep" vulnerability
        // https://github.com/robertdavidgraham/rdpscan
        $guid_475F1C8A_F70D_45C0_95E5_EB783935277D_str = "475F1C8A-F70D-45C0-95E5-EB783935277D" ascii wide nocase
        $guid_475F1C8A_F70D_45C0_95E5_EB783935277D_bin = { 8A 1C 5F 47 0D F7 C0 45 95 E5 EB 78 39 35 27 7D }

        // Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // https://github.com/ricardojoserf/NativeDump
        $guid_476FC126_239F_4D58_8389_E1C0E93C2C5E_str = "476FC126-239F-4D58-8389-E1C0E93C2C5E" ascii wide nocase
        $guid_476FC126_239F_4D58_8389_E1C0E93C2C5E_bin = { 26 C1 6F 47 9F 23 58 4D 83 89 E1 C0 E9 3C 2C 5E }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_487B9D03_F5C6_45D5_A159_3148F98B5179_str = "487B9D03-F5C6-45D5-A159-3148F98B5179" ascii wide nocase
        $guid_487B9D03_F5C6_45D5_A159_3148F98B5179_bin = { 03 9D 7B 48 C6 F5 D5 45 A1 59 31 48 F9 8B 51 79 }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_487E2246_72F1_4BD3_AA8A_A9B8C79C9F28_str = "487E2246-72F1-4BD3-AA8A-A9B8C79C9F28" ascii wide nocase
        $guid_487E2246_72F1_4BD3_AA8A_A9B8C79C9F28_bin = { 46 22 7E 48 F1 72 D3 4B AA 8A A9 B8 C7 9C 9F 28 }

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_497CA37F_506C_46CD_9B8D_F9BB0DA34B95_str = "497CA37F-506C-46CD-9B8D-F9BB0DA34B95" ascii wide nocase
        $guid_497CA37F_506C_46CD_9B8D_F9BB0DA34B95_bin = { 7F A3 7C 49 6C 50 CD 46 9B 8D F9 BB 0D A3 4B 95 }

        // Moriarty is designed to enumerate missing KBs -  detect various vulnerabilities and suggest potential exploits for Privilege Escalation in Windows environments.
        // https://github.com/BC-SECURITY/Moriarty
        $guid_49AD5F38_9E37_4967_9E84_FE19C7434ED7_str = "49AD5F38-9E37-4967-9E84-FE19C7434ED7" ascii wide nocase
        $guid_49AD5F38_9E37_4967_9E84_FE19C7434ED7_bin = { 38 5F AD 49 37 9E 67 49 9E 84 FE 19 C7 43 4E D7 }

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_4B2E3A60_9A8F_4F36_8692_14ED9887E7BE_str = "4B2E3A60-9A8F-4F36-8692-14ED9887E7BE" ascii wide nocase
        $guid_4B2E3A60_9A8F_4F36_8692_14ED9887E7BE_bin = { 60 3A 2E 4B 8F 9A 36 4F 86 92 14 ED 98 87 E7 BE }

        // Command and control server - multi-person collaborative penetration testing graphical framework
        // https://github.com/INotGreen/Xiebro-Plugins
        $guid_4B37C8BF_B1C1_4025_93C6_C3B501CBB152_str = "4B37C8BF-B1C1-4025-93C6-C3B501CBB152" ascii wide nocase
        $guid_4B37C8BF_B1C1_4025_93C6_C3B501CBB152_bin = { BF C8 37 4B C1 B1 25 40 93 C6 C3 B5 01 CB B1 52 }

        // A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // https://www.duckdns.org/install.jsp
        $guid_4B9C98F6_AF30_4280_873D_B45C7A7B89EB_str = "4B9C98F6-AF30-4280-873D-B45C7A7B89EB" ascii wide nocase
        $guid_4B9C98F6_AF30_4280_873D_B45C7A7B89EB_bin = { F6 98 9C 4B 30 AF 80 42 87 3D B4 5C 7A 7B 89 EB }

        // Documents Exfiltration and C2 project
        // https://github.com/TheD1rkMtr/DocPlz
        $guid_4C3B106C_8782_4374_9459_851749072123_str = "4C3B106C-8782-4374-9459-851749072123" ascii wide nocase
        $guid_4C3B106C_8782_4374_9459_851749072123_bin = { 6C 10 3B 4C 82 87 74 43 94 59 85 17 49 07 21 23 }

        // manage user right without secpol.msc
        // https://github.com/daem0nc0re/PrivFu
        $guid_4C496D14_FA2B_428C_BB15_20B25BAB9B73_str = "4C496D14-FA2B-428C-BB15-20B25BAB9B73" ascii wide nocase
        $guid_4C496D14_FA2B_428C_BB15_20B25BAB9B73_bin = { 14 6D 49 4C 2B FA 8C 42 BB 15 20 B2 5B AB 9B 73 }

        // Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // https://github.com/daem0nc0re/PrivFu
        $guid_4C574B86_DC07_47EA_BB02_FD50AE002910_str = "4C574B86-DC07-47EA-BB02-FD50AE002910" ascii wide nocase
        $guid_4C574B86_DC07_47EA_BB02_FD50AE002910_bin = { 86 4B 57 4C 07 DC EA 47 BB 02 FD 50 AE 00 29 10 }

        // Kernel Mode WinDbg extension for token privilege edit
        // https://github.com/daem0nc0re/PrivFu
        $guid_4C61F4EA_D946_4AF2_924B_7A873B4D964B_str = "4C61F4EA-D946-4AF2-924B-7A873B4D964B" ascii wide nocase
        $guid_4C61F4EA_D946_4AF2_924B_7A873B4D964B_bin = { EA F4 61 4C 46 D9 F2 4A 92 4B 7A 87 3B 4D 96 4B }

        // Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // https://github.com/ly4k/SpoolFool
        $guid_4c7714ee_c58d_4ef7_98f2_b162baec0ee0_str = "4c7714ee-c58d-4ef7-98f2-b162baec0ee0" ascii wide nocase
        $guid_4c7714ee_c58d_4ef7_98f2_b162baec0ee0_bin = { EE 14 77 4C 8D C5 F7 4E 98 F2 B1 62 BA EC 0E E0 }

        // reads all computer information related to successful (4624) or failed (4625) logins on the local machine to quickly identify operations and maintenance personnel during internal network penetration
        // https://github.com/uknowsec/SharpEventLog
        $guid_4CA05D5C_AF6B_4F45_81E0_788BAA8D11A2_str = "4CA05D5C-AF6B-4F45-81E0-788BAA8D11A2" ascii wide nocase
        $guid_4CA05D5C_AF6B_4F45_81E0_788BAA8D11A2_bin = { 5C 5D A0 4C 6B AF 45 4F 81 E0 78 8B AA 8D 11 A2 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_4D164EDE_7180_4A1B_BE82_59BB87542037_str = "4D164EDE-7180-4A1B-BE82-59BB87542037" ascii wide nocase
        $guid_4D164EDE_7180_4A1B_BE82_59BB87542037_bin = { DE 4E 16 4D 80 71 1B 4A BE 82 59 BB 87 54 20 37 }

        // Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // https://github.com/reveng007/DarkWidow
        $guid_4D1B765D_1287_45B1_AEDC_C4B96CF5CAA2_str = "4D1B765D-1287-45B1-AEDC-C4B96CF5CAA2" ascii wide nocase
        $guid_4D1B765D_1287_45B1_AEDC_C4B96CF5CAA2_bin = { 5D 76 1B 4D 87 12 B1 45 AE DC C4 B9 6C F5 CA A2 }

        // UAC bypass for x64 Windows 7 - 11
        // https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $guid_4d3bae5b_eb71_413b_adb2_a58f1fa2ad64_str = "4d3bae5b-eb71-413b-adb2-a58f1fa2ad64" ascii wide nocase
        $guid_4d3bae5b_eb71_413b_adb2_a58f1fa2ad64_bin = { 5B AE 3B 4D 71 EB 3B 41 AD B2 A5 8F 1F A2 AD 64 }

        // Koh is a C# and Beacon Object File (BOF) toolset that allows for the capture of user credential material via purposeful token/logon session leakage.
        // https://github.com/GhostPack/Koh
        $guid_4d5350c8_7f8c_47cf_8cde_c752018af17e_str = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii wide nocase
        $guid_4d5350c8_7f8c_47cf_8cde_c752018af17e_bin = { C8 50 53 4D 8C 7F CF 47 8C DE C7 52 01 8A F1 7E }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_4D71336E_6EF6_4DF1_8457_B94DC3D73FE7_str = "4D71336E-6EF6-4DF1-8457-B94DC3D73FE7" ascii wide nocase
        $guid_4D71336E_6EF6_4DF1_8457_B94DC3D73FE7_bin = { 6E 33 71 4D F6 6E F1 4D 84 57 B9 4D C3 D7 3F E7 }

        // SingleDose is a framework to build shellcode load/process injection techniques
        // https://github.com/Wra7h/SingleDose
        $guid_4D7AEF0B_5AA6_4AE5_971E_7141AA1FDAFC_str = "4D7AEF0B-5AA6-4AE5-971E-7141AA1FDAFC" ascii wide nocase
        $guid_4D7AEF0B_5AA6_4AE5_971E_7141AA1FDAFC_bin = { 0B EF 7A 4D A6 5A E5 4A 97 1E 71 41 AA 1F DA FC }

        // GhostMapper involves modifying Windows system "dump_" prefix drivers to exploit crash handling mechanisms for malicious purposes.
        // https://github.com/Oliver-1-1/GhostMapper
        $guid_4D7BA537_54EC_4005_9CC2_AE134B4526F9_str = "4D7BA537-54EC-4005-9CC2-AE134B4526F9" ascii wide nocase
        $guid_4D7BA537_54EC_4005_9CC2_AE134B4526F9_bin = { 37 A5 7B 4D EC 54 05 40 9C C2 AE 13 4B 45 26 F9 }

        // Lifetime AMSI bypass by @ZeroMemoryEx ported to .NET Framework 4.8
        // https://github.com/S1lkys/SharpKiller
        $guid_4DD3206C_F14A_43A3_8EA8_88676810B8CD_str = "4DD3206C-F14A-43A3-8EA8-88676810B8CD" ascii wide nocase
        $guid_4DD3206C_F14A_43A3_8EA8_88676810B8CD_bin = { 6C 20 D3 4D 4A F1 A3 43 8E A8 88 67 68 10 B8 CD }

        // unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $guid_4DE43724_3851_4376_BB6C_EA15CF500C44_str = "4DE43724-3851-4376-BB6C-EA15CF500C44" ascii wide nocase
        $guid_4DE43724_3851_4376_BB6C_EA15CF500C44_bin = { 24 37 E4 4D 51 38 76 43 BB 6C EA 15 CF 50 0C 44 }

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_4ED3C17D_33E6_4B86_9FA0_DA774B7CD387_str = "4ED3C17D-33E6-4B86-9FA0-DA774B7CD387" ascii wide nocase
        $guid_4ED3C17D_33E6_4B86_9FA0_DA774B7CD387_bin = { 7D C1 D3 4E E6 33 86 4B 9F A0 DA 77 4B 7C D3 87 }

        // Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // https://github.com/Mayyhem/Maestro
        $guid_4EE2C7E8_095D_490A_9465_9B4BB9070669_str = "4EE2C7E8-095D-490A-9465-9B4BB9070669" ascii wide nocase
        $guid_4EE2C7E8_095D_490A_9465_9B4BB9070669_bin = { E8 C7 E2 4E 5D 09 0A 49 94 65 9B 4B B9 07 06 69 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_4EF73752_78B0_4E0D_A33B_B6637B6C2177_str = "4EF73752-78B0-4E0D-A33B-B6637B6C2177" ascii wide nocase
        $guid_4EF73752_78B0_4E0D_A33B_B6637B6C2177_bin = { 52 37 F7 4E B0 78 0D 4E A3 3B B6 63 7B 6C 21 77 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_4F169EA5_8854_4258_9D2C_D44F37D88776_str = "4F169EA5-8854-4258-9D2C-D44F37D88776" ascii wide nocase
        $guid_4F169EA5_8854_4258_9D2C_D44F37D88776_bin = { A5 9E 16 4F 54 88 58 42 9D 2C D4 4F 37 D8 87 76 }

        // Abuses the Windows containers framework to bypass EDRs.
        // https://github.com/deepinstinct/ContainYourself
        $guid_4F2AD0E0_8C4D_45CB_97DE_CE8D4177E7BF_str = "4F2AD0E0-8C4D-45CB-97DE-CE8D4177E7BF" ascii wide nocase
        $guid_4F2AD0E0_8C4D_45CB_97DE_CE8D4177E7BF_bin = { E0 D0 2A 4F 4D 8C CB 45 97 DE CE 8D 41 77 E7 BF }

        // Manage everything in one place
        // https://github.com/fleetdm/fleet
        $guid_4F748D41_5BE1_4626_A0AB_9EA15CDC2074_str = "4F748D41-5BE1-4626-A0AB-9EA15CDC2074" ascii wide nocase
        $guid_4F748D41_5BE1_4626_A0AB_9EA15CDC2074_bin = { 41 8D 74 4F E1 5B 26 46 A0 AB 9E A1 5C DC 20 74 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_4FB03AD0_96FF_4730_801A_4F997795D920_str = "4FB03AD0-96FF-4730-801A-4F997795D920" ascii wide nocase
        $guid_4FB03AD0_96FF_4730_801A_4F997795D920_bin = { D0 3A B0 4F FF 96 30 47 80 1A 4F 99 77 95 D9 20 }

        // SAM dumping via the registry in C#/.NET
        // https://github.com/jojonas/SharpSAMDump
        $guid_4FEAB888_F514_4F2E_A4F7_5989A86A69DE_str = "4FEAB888-F514-4F2E-A4F7-5989A86A69DE" ascii wide nocase
        $guid_4FEAB888_F514_4F2E_A4F7_5989A86A69DE_bin = { 88 B8 EA 4F 14 F5 2E 4F A4 F7 59 89 A8 6A 69 DE }

        // A C# Command & Control framework
        // https://github.com/DragoQCC/HardHatC2
        $guid_5010BEE8_0944_4655_987F_AB3BB376E774_str = "5010BEE8-0944-4655-987F-AB3BB376E774" ascii wide nocase
        $guid_5010BEE8_0944_4655_987F_AB3BB376E774_bin = { E8 BE 10 50 44 09 55 46 98 7F AB 3B B3 76 E7 74 }

        // Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // https://github.com/p3nt4/PowerShdll
        $guid_5067F916_9971_47D6_BBCB_85FB3982584F_str = "5067F916-9971-47D6-BBCB-85FB3982584F" ascii wide nocase
        $guid_5067F916_9971_47D6_BBCB_85FB3982584F_bin = { 16 F9 67 50 71 99 D6 47 BB CB 85 FB 39 82 58 4F }

        // Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
        // https://github.com/Metro-Holografix/DInjector
        $guid_5086CE01_1032_4CA3_A302_6CFF2A8B64DC_str = "5086CE01-1032-4CA3-A302-6CFF2A8B64DC" ascii wide nocase
        $guid_5086CE01_1032_4CA3_A302_6CFF2A8B64DC_bin = { 01 CE 86 50 32 10 A3 4C A3 02 6C FF 2A 8B 64 DC }

        // DCOM Lateral Movement
        // https://github.com/rvrsh3ll/SharpCOM
        $guid_51960F7D_76FE_499F_AFBD_ACABD7BA50D1_str = "51960F7D-76FE-499F-AFBD-ACABD7BA50D1" ascii wide nocase
        $guid_51960F7D_76FE_499F_AFBD_ACABD7BA50D1_bin = { 7D 0F 96 51 FE 76 9F 49 AF BD AC AB D7 BA 50 D1 }

        // Asynchronous Password Spraying Tool in C# for Windows Environments
        // https://github.com/ustayready/SharpHose
        $guid_51C6E016_1428_441D_82E9_BB0EB599BBC8_str = "51C6E016-1428-441D-82E9-BB0EB599BBC8" ascii wide nocase
        $guid_51C6E016_1428_441D_82E9_BB0EB599BBC8_bin = { 16 E0 C6 51 28 14 1D 44 82 E9 BB 0E B5 99 BB C8 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_51E46096_4A36_4C7D_9773_BC28DBDC4FC6_str = "51E46096-4A36-4C7D-9773-BC28DBDC4FC6" ascii wide nocase
        $guid_51E46096_4A36_4C7D_9773_BC28DBDC4FC6_bin = { 96 60 E4 51 36 4A 7D 4C 97 73 BC 28 DB DC 4F C6 }

        // SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // https://github.com/cobbr/SharpSploit
        $guid_52040049_D7FC_4C72_B6AE_BD2C7AB27DEE_str = "52040049-D7FC-4C72-B6AE-BD2C7AB27DEE" ascii wide nocase
        $guid_52040049_D7FC_4C72_B6AE_BD2C7AB27DEE_bin = { 49 00 04 52 FC D7 72 4C B6 AE BD 2C 7A B2 7D EE }

        // BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // https://github.com/AlessandroZ/BeRoot
        $guid_52B0FF57_7E0A_4CA9_84D4_58DFA2456BA5_str = "52B0FF57-7E0A-4CA9-84D4-58DFA2456BA5" ascii wide nocase
        $guid_52B0FF57_7E0A_4CA9_84D4_58DFA2456BA5_bin = { 57 FF B0 52 0A 7E A9 4C 84 D4 58 DF A2 45 6B A5 }

        // active directory weakness scan Vulnerability scanner
        // https://github.com/netwrix/pingcastle
        $guid_52BBA3C2_A74E_4096_B65F_B88C38F92120_str = "52BBA3C2-A74E-4096-B65F-B88C38F92120" ascii wide nocase
        $guid_52BBA3C2_A74E_4096_B65F_B88C38F92120_bin = { C2 A3 BB 52 4E A7 96 40 B6 5F B8 8C 38 F9 21 20 }

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_53182258_F40E_4104_AFC6_1F327E556E77_str = "53182258-F40E-4104-AFC6-1F327E556E77" ascii wide nocase
        $guid_53182258_F40E_4104_AFC6_1F327E556E77_bin = { 58 22 18 53 0E F4 04 41 AF C6 1F 32 7E 55 6E 77 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_534D9A24_3138_4209_A4C6_6B9C1EF0B579_str = "534D9A24-3138-4209-A4C6-6B9C1EF0B579" ascii wide nocase
        $guid_534D9A24_3138_4209_A4C6_6B9C1EF0B579_bin = { 24 9A 4D 53 38 31 09 42 A4 C6 6B 9C 1E F0 B5 79 }

        // injection technique abusing windows fork API to evade EDRs
        // https://github.com/deepinstinct/Dirty-Vanity
        $guid_53891DF6_3F6D_DE4B_A8CD_D89E94D0C8CD_str = "53891DF6-3F6D-DE4B-A8CD-D89E94D0C8CD" ascii wide nocase
        $guid_53891DF6_3F6D_DE4B_A8CD_D89E94D0C8CD_bin = { F6 1D 89 53 6D 3F 4B DE A8 CD D8 9E 94 D0 C8 CD }

        // This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // https://github.com/nettitude/MalSCCM
        $guid_5439CECD_3BB3_4807_B33F_E4C299B71CA2_str = "5439CECD-3BB3-4807-B33F-E4C299B71CA2" ascii wide nocase
        $guid_5439CECD_3BB3_4807_B33F_E4C299B71CA2_bin = { CD CE 39 54 B3 3B 07 48 B3 3F E4 C2 99 B7 1C A2 }

        // similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // https://github.com/CICADA8-Research/RemoteKrbRelay
        $guid_5494EDD3_132D_4238_AC25_FA384D78D4E3_str = "5494EDD3-132D-4238-AC25-FA384D78D4E3" ascii wide nocase
        $guid_5494EDD3_132D_4238_AC25_FA384D78D4E3_bin = { D3 ED 94 54 2D 13 38 42 AC 25 FA 38 4D 78 D4 E3 }

        // walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // https://github.com/malcomvetter/Periscope
        $guid_5531A5C5_8710_48AD_BEFE_88E26F6CF798_str = "5531A5C5-8710-48AD-BEFE-88E26F6CF798" ascii wide nocase
        $guid_5531A5C5_8710_48AD_BEFE_88E26F6CF798_bin = { C5 A5 31 55 10 87 AD 48 BE FE 88 E2 6F 6C F7 98 }

        // NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // https://github.com/bitsadmin/nopowershell
        $guid_555AD0AC_1FDB_4016_8257_170A74CB2F55_str = "555AD0AC-1FDB-4016-8257-170A74CB2F55" ascii wide nocase
        $guid_555AD0AC_1FDB_4016_8257_170A74CB2F55_bin = { AC D0 5A 55 DB 1F 16 40 82 57 17 0A 74 CB 2F 55 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_55625889_F7BB_4533_9702_DDE98FBB0DDF_str = "55625889-F7BB-4533-9702-DDE98FBB0DDF" ascii wide nocase
        $guid_55625889_F7BB_4533_9702_DDE98FBB0DDF_bin = { 89 58 62 55 BB F7 33 45 97 02 DD E9 8F BB 0D DF }

        // A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // https://github.com/OmriBaso/BesoToken
        $guid_55A48A19_1A5C_4E0D_A46A_5DB04C1D8B03_str = "55A48A19-1A5C-4E0D-A46A-5DB04C1D8B03" ascii wide nocase
        $guid_55A48A19_1A5C_4E0D_A46A_5DB04C1D8B03_bin = { 19 8A A4 55 5C 1A 0D 4E A4 6A 5D B0 4C 1D 8B 03 }

        // Block any Process to open HANDLE to your process - only SYTEM is allowed to open handle to your process - with that you can avoid remote memory scanners
        // https://github.com/TheD1rkMtr/BlockOpenHandle
        $guid_55F0368B_63DA_40E7_A8A5_289F70DF9C7F_str = "55F0368B-63DA-40E7-A8A5-289F70DF9C7F" ascii wide nocase
        $guid_55F0368B_63DA_40E7_A8A5_289F70DF9C7F_bin = { 8B 36 F0 55 DA 63 E7 40 A8 A5 28 9F 70 DF 9C 7F }

        // Payload Generation Framework
        // https://github.com/mdsecactivebreach/SharpShooter
        $guid_56598F1C_6D88_4994_A392_AF337ABE5777_str = "56598F1C-6D88-4994-A392-AF337ABE5777" ascii wide nocase
        $guid_56598F1C_6D88_4994_A392_AF337ABE5777_bin = { 1C 8F 59 56 88 6D 94 49 A3 92 AF 33 7A BE 57 77 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_56F981FD_634A_4656_85A7_5636658E1F94_str = "56F981FD-634A-4656-85A7-5636658E1F94" ascii wide nocase
        $guid_56F981FD_634A_4656_85A7_5636658E1F94_bin = { FD 81 F9 56 4A 63 56 46 85 A7 56 36 65 8E 1F 94 }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_5745976E_48A7_4F79_9BAA_82D1F43D1261_str = "5745976E-48A7-4F79-9BAA-82D1F43D1261" ascii wide nocase
        $guid_5745976E_48A7_4F79_9BAA_82D1F43D1261_bin = { 6E 97 45 57 A7 48 79 4F 9B AA 82 D1 F4 3D 12 61 }

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_5782C660_DD26_40DC_B06C_B9275371EC55_str = "5782C660-DD26-40DC-B06C-B9275371EC55" ascii wide nocase
        $guid_5782C660_DD26_40DC_B06C_B9275371EC55_bin = { 60 C6 82 57 26 DD DC 40 B0 6C B9 27 53 71 EC 55 }

        // Utility to craft HTML or SVG smuggled files for Red Team engagements
        // https://github.com/surajpkhetani/AutoSmuggle
        $guid_57A893C7_7527_4B55_B4E9_D644BBDA89D1_str = "57A893C7-7527-4B55-B4E9-D644BBDA89D1" ascii wide nocase
        $guid_57A893C7_7527_4B55_B4E9_D644BBDA89D1_bin = { C7 93 A8 57 27 75 55 4B B4 E9 D6 44 BB DA 89 D1 }

        // This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // https://github.com/redskal/SharpAzbelt
        $guid_57D4D4F4_F083_47A3_AE33_AE2500ABA3B6_str = "57D4D4F4-F083-47A3-AE33-AE2500ABA3B6" ascii wide nocase
        $guid_57D4D4F4_F083_47A3_AE33_AE2500ABA3B6_bin = { F4 D4 D4 57 83 F0 A3 47 AE 33 AE 25 00 AB A3 B6 }

        // DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // https://github.com/deepinstinct/DCOMUploadExec
        $guid_57FD94EC_4361_43FD_AB9D_CDB254C0DE8F_str = "57FD94EC-4361-43FD-AB9D-CDB254C0DE8F" ascii wide nocase
        $guid_57FD94EC_4361_43FD_AB9D_CDB254C0DE8F_bin = { EC 94 FD 57 61 43 FD 43 AB 9D CD B2 54 C0 DE 8F }

        // Creating a persistent service
        // https://github.com/uknowsec/CreateService
        $guid_580ba177_cf9a_458c_a692_36dd6f23ea77_str = "580ba177-cf9a-458c-a692-36dd6f23ea77" ascii wide nocase
        $guid_580ba177_cf9a_458c_a692_36dd6f23ea77_bin = { 77 A1 0B 58 9A CF 8C 45 A6 92 36 DD 6F 23 EA 77 }

        // LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // https://github.com/CCob/MirrorDump
        $guid_58338E42_6010_493C_B8C8_2FD2CFC30FFB_str = "58338E42-6010-493C-B8C8-2FD2CFC30FFB" ascii wide nocase
        $guid_58338E42_6010_493C_B8C8_2FD2CFC30FFB_bin = { 42 8E 33 58 10 60 3C 49 B8 C8 2F D2 CF C3 0F FB }

        // A fake AMSI Provider which can be used for persistence
        // https://github.com/netbiosX/AMSI-Provider
        $guid_58B32FCA_F385_4500_9A8E_7CBA1FC9BA13_str = "58B32FCA-F385-4500-9A8E-7CBA1FC9BA13" ascii wide nocase
        $guid_58B32FCA_F385_4500_9A8E_7CBA1FC9BA13_bin = { CA 2F B3 58 85 F3 00 45 9A 8E 7C BA 1F C9 BA 13 }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_59224C16_39C5_49EA_8525_F493DC1D66FE_str = "59224C16-39C5-49EA-8525-F493DC1D66FE" ascii wide nocase
        $guid_59224C16_39C5_49EA_8525_F493DC1D66FE_bin = { 16 4C 22 59 C5 39 EA 49 85 25 F4 93 DC 1D 66 FE }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_595D5812_AA30_4EDE_95DA_8EDD7B8844BD_str = "595D5812-AA30-4EDE-95DA-8EDD7B8844BD" ascii wide nocase
        $guid_595D5812_AA30_4EDE_95DA_8EDD7B8844BD_bin = { 12 58 5D 59 30 AA DE 4E 95 DA 8E DD 7B 88 44 BD }

        // MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // https://github.com/senzee1984/MutationGate
        $guid_5A0FBE0D_BACC_4B97_8578_B5B27567EEA7_str = "5A0FBE0D-BACC-4B97-8578-B5B27567EEA7" ascii wide nocase
        $guid_5A0FBE0D_BACC_4B97_8578_B5B27567EEA7_bin = { 0D BE 0F 5A CC BA 97 4B 85 78 B5 B2 75 67 EE A7 }

        // a very fast brute force webshell password tool
        // https://github.com/shmilylty/cheetah
        $guid_5a1f9b0e_9f7c_4673_bf16_4740707f41b7_str = "5a1f9b0e-9f7c-4673-bf16-4740707f41b7" ascii wide nocase
        $guid_5a1f9b0e_9f7c_4673_bf16_4740707f41b7_bin = { 0E 9B 1F 5A 7C 9F 73 46 BF 16 47 40 70 7F 41 B7 }

        // Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // https://github.com/TheD1rkMtr/Pspersist
        $guid_5A403F3C_9136_4B67_A94E_02D3BCD3162D_str = "5A403F3C-9136-4B67-A94E-02D3BCD3162D" ascii wide nocase
        $guid_5A403F3C_9136_4B67_A94E_02D3BCD3162D_bin = { 3C 3F 40 5A 36 91 67 4B A9 4E 02 D3 BC D3 16 2D }

        // Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // https://github.com/TheD1rkMtr/StackCrypt
        $guid_5A6F942E_888A_4CE1_A6FB_1AB8AE22AFFA_str = "5A6F942E-888A-4CE1-A6FB-1AB8AE22AFFA" ascii wide nocase
        $guid_5A6F942E_888A_4CE1_A6FB_1AB8AE22AFFA_bin = { 2E 94 6F 5A 8A 88 E1 4C A6 FB 1A B8 AE 22 AF FA }

        // Windows rootkit designed to work with BYOVD exploits
        // https://github.com/ColeHouston/Sunder
        $guid_5a958c89_6327_401c_a214_c89e54855b57_str = "5a958c89-6327-401c-a214-c89e54855b57" ascii wide nocase
        $guid_5a958c89_6327_401c_a214_c89e54855b57_bin = { 89 8C 95 5A 27 63 1C 40 A2 14 C8 9E 54 85 5B 57 }

        // Executes PowerShell from an unmanaged process
        // https://github.com/leechristensen/UnmanagedPowerShell
        $guid_5A9955E4_62B7_419D_AB73_01A6D7DD27FC_str = "5A9955E4-62B7-419D-AB73-01A6D7DD27FC" ascii wide nocase
        $guid_5A9955E4_62B7_419D_AB73_01A6D7DD27FC_bin = { E4 55 99 5A B7 62 9D 41 AB 73 01 A6 D7 DD 27 FC }

        // using RasMan service for privilege escalation
        // https://github.com/crisprss/RasmanPotato
        $guid_5AC309CE_1223_4FF5_AF84_24BCD0B9E4DC_str = "5AC309CE-1223-4FF5-AF84-24BCD0B9E4DC" ascii wide nocase
        $guid_5AC309CE_1223_4FF5_AF84_24BCD0B9E4DC_bin = { CE 09 C3 5A 23 12 F5 4F AF 84 24 BC D0 B9 E4 DC }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_5b2ec674_0aa4_4209_94df_b6c995ad59c4_str = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" ascii wide nocase
        $guid_5b2ec674_0aa4_4209_94df_b6c995ad59c4_bin = { 74 C6 2E 5B A4 0A 09 42 94 DF B6 C9 95 AD 59 C4 }

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1_str = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" ascii wide nocase
        $guid_5B5EF20C_9289_4E78_A8AF_2D30E44CF4F1_bin = { 0C F2 5E 5B 89 92 78 4E A8 AF 2D 30 E4 4C F4 F1 }

        // Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // https://github.com/Meltedd/HVNC
        $guid_5C3AD9AC_C62C_4AA8_BAE2_9AF920A652E3_str = "5C3AD9AC-C62C-4AA8-BAE2-9AF920A652E3" ascii wide nocase
        $guid_5C3AD9AC_C62C_4AA8_BAE2_9AF920A652E3_bin = { AC D9 3A 5C 2C C6 A8 4A BA E2 9A F9 20 A6 52 E3 }

        // a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // https://github.com/zeze-zeze/NamedPipeMaster
        $guid_5C87B2E6_8D24_4F1D_AB85_FC659F452AD0_str = "5C87B2E6-8D24-4F1D-AB85-FC659F452AD0" ascii wide nocase
        $guid_5C87B2E6_8D24_4F1D_AB85_FC659F452AD0_bin = { E6 B2 87 5C 24 8D 1D 4F AB 85 FC 65 9F 45 2A D0 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_5D01A326_0357_4C3F_A196_3B8B866C9613_str = "5D01A326-0357-4C3F-A196-3B8B866C9613" ascii wide nocase
        $guid_5D01A326_0357_4C3F_A196_3B8B866C9613_bin = { 26 A3 01 5D 57 03 3F 4C A1 96 3B 8B 86 6C 96 13 }

        // How to spoof the command line when spawning a new process from C#
        // https://github.com/plackyhacker/CmdLineSpoofer
        $guid_5D03EFC2_72E9_4410_B147_0A1A5C743999_str = "5D03EFC2-72E9-4410-B147-0A1A5C743999" ascii wide nocase
        $guid_5D03EFC2_72E9_4410_B147_0A1A5C743999_bin = { C2 EF 03 5D E9 72 10 44 B1 47 0A 1A 5C 74 39 99 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_5D10ED0A_6C52_49FE_90F5_CFAAECA8FABE_str = "5D10ED0A-6C52-49FE-90F5-CFAAECA8FABE" ascii wide nocase
        $guid_5D10ED0A_6C52_49FE_90F5_CFAAECA8FABE_bin = { 0A ED 10 5D 52 6C FE 49 90 F5 CF AA EC A8 FA BE }

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2_str = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" ascii wide nocase
        $guid_5D21B8F0_3824_4D15_9911_1E51F2416BC2_bin = { F0 B8 21 5D 24 38 15 4D 99 11 1E 51 F2 41 6B C2 }

        // Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // https://github.com/CCob/Shwmae
        $guid_5D3EF551_3D1F_468E_A75B_764F436D577D_str = "5D3EF551-3D1F-468E-A75B-764F436D577D" ascii wide nocase
        $guid_5D3EF551_3D1F_468E_A75B_764F436D577D_bin = { 51 F5 3E 5D 1F 3D 8E 46 A7 5B 76 4F 43 6D 57 7D }

        // SCRIPTBLOCK SMUGGLING: SPOOFING POWERSHELL SECURITY LOGS AND BYPASSING AMSI WITHOUT REFLECTION OR PATCHING
        // https://github.com/BC-SECURITY/ScriptBlock-Smuggling
        $guid_5D4E7C1F_4812_4038_9663_6CD277ED9AD4_str = "5D4E7C1F-4812-4038-9663-6CD277ED9AD4" ascii wide nocase
        $guid_5D4E7C1F_4812_4038_9663_6CD277ED9AD4_bin = { 1F 7C 4E 5D 12 48 38 40 96 63 6C D2 77 ED 9A D4 }

        // C# executables to extract information from target environment using OneDrive API.
        // https://github.com/adm1nPanda/SharpExfil
        $guid_5de78ea9_73a8_4c53_9d5e_3a893e439a3a_str = "5de78ea9-73a8-4c53-9d5e-3a893e439a3a" ascii wide nocase
        $guid_5de78ea9_73a8_4c53_9d5e_3a893e439a3a_bin = { A9 8E E7 5D A8 73 53 4C 9D 5E 3A 89 3E 43 9A 3A }

        // Extracts passwords from a KeePass 2.x database directly from memory
        // https://github.com/denandz/KeeFarce
        $guid_5DE7F97C_B97B_489F_A1E4_9F9656317F94_str = "5DE7F97C-B97B-489F-A1E4-9F9656317F94" ascii wide nocase
        $guid_5DE7F97C_B97B_489F_A1E4_9F9656317F94_bin = { 7C F9 E7 5D 7B B9 9F 48 A1 E4 9F 96 56 31 7F 94 }

        // Documents Exfiltration and C2 project
        // https://github.com/TheD1rkMtr/DocPlz
        $guid_5E0812A9_C727_44F3_A2E3_8286CDC3ED4F_str = "5E0812A9-C727-44F3-A2E3-8286CDC3ED4F" ascii wide nocase
        $guid_5E0812A9_C727_44F3_A2E3_8286CDC3ED4F_bin = { A9 12 08 5E 27 C7 F3 44 A2 E3 82 86 CD C3 ED 4F }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_5E9715AB_CAF7_4FFF_8E14_A8727891DA93_str = "5E9715AB-CAF7-4FFF-8E14-A8727891DA93" ascii wide nocase
        $guid_5E9715AB_CAF7_4FFF_8E14_A8727891DA93_bin = { AB 15 97 5E F7 CA FF 4F 8E 14 A8 72 78 91 DA 93 }

        // extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // https://github.com/0xsp-SRD/MDE_Enum
        $guid_5EC16C3F_1E62_4661_8C20_504CB0E55441_str = "5EC16C3F-1E62-4661-8C20-504CB0E55441" ascii wide nocase
        $guid_5EC16C3F_1E62_4661_8C20_504CB0E55441_bin = { 3F 6C C1 5E 62 1E 61 46 8C 20 50 4C B0 E5 54 41 }

        // allowing the execution of Powershell functionality without the use of Powershell.exe
        // https://github.com/PowerShellEmpire/PowerTools
        $guid_5ED2F78E_8538_4C87_BCED_E19E9DAD879C_str = "5ED2F78E-8538-4C87-BCED-E19E9DAD879C" ascii wide nocase
        $guid_5ED2F78E_8538_4C87_BCED_E19E9DAD879C_bin = { 8E F7 D2 5E 38 85 87 4C BC ED E1 9E 9D AD 87 9C }

        // SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
        // https://github.com/GhostPack/SharpDPAPI
        $guid_5F026C27_F8E6_4052_B231_8451C6A73838_str = "5F026C27-F8E6-4052-B231-8451C6A73838" ascii wide nocase
        $guid_5F026C27_F8E6_4052_B231_8451C6A73838_bin = { 27 6C 02 5F E6 F8 52 40 B2 31 84 51 C6 A7 38 38 }

        // Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // https://github.com/Imanfeng/Telemetry
        $guid_5f026c27_f8e6_4052_b231_8451c6a73838_str = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii wide nocase
        $guid_5f026c27_f8e6_4052_b231_8451c6a73838_bin = { 27 6C 02 5F E6 F8 52 40 B2 31 84 51 C6 A7 38 38 }

        // Bypassing UAC with SSPI Datagram Contexts
        // https://github.com/antonioCoco/SspiUacBypass
        $guid_5F4DC47F_7819_4528_9C16_C88F1BE97EC5_str = "5F4DC47F-7819-4528-9C16-C88F1BE97EC5" ascii wide nocase
        $guid_5F4DC47F_7819_4528_9C16_C88F1BE97EC5_bin = { 7F C4 4D 5F 19 78 28 45 9C 16 C8 8F 1B E9 7E C5 }

        // SingleDose is a framework to build shellcode load/process injection techniques
        // https://github.com/Wra7h/SingleDose
        $guid_5FAC3991_D4FD_4227_B73D_BEE34EB89987_str = "5FAC3991-D4FD-4227-B73D-BEE34EB89987" ascii wide nocase
        $guid_5FAC3991_D4FD_4227_B73D_BEE34EB89987_bin = { 91 39 AC 5F FD D4 27 42 B7 3D BE E3 4E B8 99 87 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_5FB1809B_B0FD_48E9_9E47_3CB048369433_str = "5FB1809B-B0FD-48E9-9E47-3CB048369433" ascii wide nocase
        $guid_5FB1809B_B0FD_48E9_9E47_3CB048369433_bin = { 9B 80 B1 5F FD B0 E9 48 9E 47 3C B0 48 36 94 33 }

        // PrintNightmare exploitation
        // https://github.com/cube0x0/CVE-2021-1675
        $guid_5FEB114B_49EC_4652_B29E_8CB5E752EC3E_str = "5FEB114B-49EC-4652-B29E-8CB5E752EC3E" ascii wide nocase
        $guid_5FEB114B_49EC_4652_B29E_8CB5E752EC3E_bin = { 4B 11 EB 5F EC 49 52 46 B2 9E 8C B5 E7 52 EC 3E }

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_60BBE2CB_585B_4DBD_9CB9_22F00D3F11E5_str = "60BBE2CB-585B-4DBD-9CB9-22F00D3F11E5" ascii wide nocase
        $guid_60BBE2CB_585B_4DBD_9CB9_22F00D3F11E5_bin = { CB E2 BB 60 5B 58 BD 4D 9C B9 22 F0 0D 3F 11 E5 }

        // HTTP/S Beaconing Implant
        // https://github.com/silentbreaksec/Throwback
        $guid_60C1DA68_85AC_43AB_9A2B_27FA345EC113_str = "60C1DA68-85AC-43AB-9A2B-27FA345EC113" ascii wide nocase
        $guid_60C1DA68_85AC_43AB_9A2B_27FA345EC113_bin = { 68 DA C1 60 AC 85 AB 43 9A 2B 27 FA 34 5E C1 13 }

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_60D02E32_1711_4D9E_9AC2_10627C52EB40_str = "60D02E32-1711-4D9E-9AC2-10627C52EB40" ascii wide nocase
        $guid_60D02E32_1711_4D9E_9AC2_10627C52EB40_bin = { 32 2E D0 60 11 17 9E 4D 9A C2 10 62 7C 52 EB 40 }

        // Open-Source Remote Administration Tool For Windows C# (RAT)
        // https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $guid_619B7612_DFEA_442A_A927_D997F99C497B_str = "619B7612-DFEA-442A-A927-D997F99C497B" ascii wide nocase
        $guid_619B7612_DFEA_442A_A927_D997F99C497B_bin = { 12 76 9B 61 EA DF 2A 44 A9 27 D9 97 F9 9C 49 7B }

        // get SYSTEM via SeImpersonate privileges
        // https://github.com/S3cur3Th1sSh1t/MultiPotato
        $guid_61CE6716_E619_483C_B535_8694F7617548_str = "61CE6716-E619-483C-B535-8694F7617548" ascii wide nocase
        $guid_61CE6716_E619_483C_B535_8694F7617548_bin = { 16 67 CE 61 19 E6 3C 48 B5 35 86 94 F7 61 75 48 }

        // Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // https://github.com/bugch3ck/SharpAltSecIds
        $guid_623F0079_5871_4237_B872_70FDFC2D8C52_str = "623F0079-5871-4237-B872-70FDFC2D8C52" ascii wide nocase
        $guid_623F0079_5871_4237_B872_70FDFC2D8C52_bin = { 79 00 3F 62 71 58 37 42 B8 72 70 FD FC 2D 8C 52 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_628E42D5_AE4F_4CDD_8D14_DAB1A3697B62_str = "628E42D5-AE4F-4CDD-8D14-DAB1A3697B62" ascii wide nocase
        $guid_628E42D5_AE4F_4CDD_8D14_DAB1A3697B62_bin = { D5 42 8E 62 4F AE DD 4C 8D 14 DA B1 A3 69 7B 62 }

        // A C# Command & Control framework
        // https://github.com/DragoQCC/HardHatC2
        $guid_62B6EF3C_3180_4730_A2CE_82D27C43A5B2_str = "62B6EF3C-3180-4730-A2CE-82D27C43A5B2" ascii wide nocase
        $guid_62B6EF3C_3180_4730_A2CE_82D27C43A5B2_bin = { 3C EF B6 62 80 31 30 47 A2 CE 82 D2 7C 43 A5 B2 }

        // Adaptive DLL hijacking / dynamic export forwarding
        // https://github.com/monoxgas/Koppeling
        $guid_62E3CCF4_07F3_496E_B77D_48D5AC0E6260_str = "62E3CCF4-07F3-496E-B77D-48D5AC0E6260" ascii wide nocase
        $guid_62E3CCF4_07F3_496E_B77D_48D5AC0E6260_bin = { F4 CC E3 62 F3 07 6E 49 B7 7D 48 D5 AC 0E 62 60 }

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_6302105A_80BB_4987_82EC_95973911238B_str = "6302105A-80BB-4987-82EC-95973911238B" ascii wide nocase
        $guid_6302105A_80BB_4987_82EC_95973911238B_bin = { 5A 10 02 63 BB 80 87 49 82 EC 95 97 39 11 23 8B }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_630BF262_768C_4085_89B1_9FEF7375F442_str = "630BF262-768C-4085-89B1-9FEF7375F442" ascii wide nocase
        $guid_630BF262_768C_4085_89B1_9FEF7375F442_bin = { 62 F2 0B 63 8C 76 85 40 89 B1 9F EF 73 75 F4 42 }

        // A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // https://github.com/PhrozenIO/SharpFtpC2
        $guid_6376A5B0_1BA8_4854_B81E_F5DC072C0FEE_str = "6376A5B0-1BA8-4854-B81E-F5DC072C0FEE" ascii wide nocase
        $guid_6376A5B0_1BA8_4854_B81E_F5DC072C0FEE_bin = { B0 A5 76 63 A8 1B 54 48 B8 1E F5 DC 07 2C 0F EE }

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_63957210_4871_42D3_B98A_191AF5F91079_str = "63957210-4871-42D3-B98A-191AF5F91079" ascii wide nocase
        $guid_63957210_4871_42D3_B98A_191AF5F91079_bin = { 10 72 95 63 71 48 D3 42 B9 8A 19 1A F5 F9 10 79 }

        // WinLicense key extraction via Intel PIN
        // https://github.com/charlesnathansmith/whatlicense
        $guid_639EF517_FCFC_408E_9500_71F0DC0458DB_str = "639EF517-FCFC-408E-9500-71F0DC0458DB" ascii wide nocase
        $guid_639EF517_FCFC_408E_9500_71F0DC0458DB_bin = { 17 F5 9E 63 FC FC 8E 40 95 00 71 F0 DC 04 58 DB }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_63CAF2AD_A016_43BD_AA27_02CB848E2067_str = "63CAF2AD-A016-43BD-AA27-02CB848E2067" ascii wide nocase
        $guid_63CAF2AD_A016_43BD_AA27_02CB848E2067_bin = { AD F2 CA 63 16 A0 BD 43 AA 27 02 CB 84 8E 20 67 }

        // Remote keylogger for Windows written in C++
        // https://github.com/shehzade/peeping-tom
        $guid_63ec96c5_075f_4f22_92ec_cf28a2f70737_str = "63ec96c5-075f-4f22-92ec-cf28a2f70737" ascii wide nocase
        $guid_63ec96c5_075f_4f22_92ec_cf28a2f70737_bin = { C5 96 EC 63 5F 07 22 4F 92 EC CF 28 A2 F7 07 37 }

        // Windows rootkit designed to work with BYOVD exploits
        // https://github.com/ColeHouston/Sunder
        $guid_643ad690_5c85_4b12_af42_2d31d11657a1_str = "643ad690-5c85-4b12-af42-2d31d11657a1" ascii wide nocase
        $guid_643ad690_5c85_4b12_af42_2d31d11657a1_bin = { 90 D6 3A 64 85 5C 12 4B AF 42 2D 31 D1 16 57 A1 }

        // DLL and PowerShell script to assist with finding DLL hijacks
        // https://github.com/slyd0g/DLLHijackTest
        $guid_644758B1_C146_4D3B_B614_8EB6C933B0AA_str = "644758B1-C146-4D3B-B614-8EB6C933B0AA" ascii wide nocase
        $guid_644758B1_C146_4D3B_B614_8EB6C933B0AA_bin = { B1 58 47 64 46 C1 3B 4D B6 14 8E B6 C9 33 B0 AA }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_644AFE4A_2267_4DF9_A79D_B514FB31830E_str = "644AFE4A-2267-4DF9-A79D-B514FB31830E" ascii wide nocase
        $guid_644AFE4A_2267_4DF9_A79D_B514FB31830E_bin = { 4A FE 4A 64 67 22 F9 4D A7 9D B5 14 FB 31 83 0E }

        // Malware RAT with keylogger - dll injection - C2 - Remote control
        // https://github.com/sin5678/gh0st
        $guid_64D26B66_8A59_0724_007F_9001C4F472A2_str = "64D26B66-8A59-0724-007F-9001C4F472A2" ascii wide nocase
        $guid_64D26B66_8A59_0724_007F_9001C4F472A2_bin = { 66 6B D2 64 59 8A 24 07 00 7F 90 01 C4 F4 72 A2 }

        // Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // https://github.com/peiga/DumpThatLSASS
        $guid_64D84D51_F462_4A24_85EA_845C97238C09_str = "64D84D51-F462-4A24-85EA-845C97238C09" ascii wide nocase
        $guid_64D84D51_F462_4A24_85EA_845C97238C09_bin = { 51 4D D8 64 62 F4 24 4A 85 EA 84 5C 97 23 8C 09 }

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_6536EBEC_014E_4D6B_97BE_223137694CA8_str = "6536EBEC-014E-4D6B-97BE-223137694CA8" ascii wide nocase
        $guid_6536EBEC_014E_4D6B_97BE_223137694CA8_bin = { EC EB 36 65 4E 01 6B 4D 97 BE 22 31 37 69 4C A8 }

        // Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // https://github.com/GhostPack/Rubeus
        $guid_658C8B7F_3664_4A95_9572_A3E5871DFC06_str = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii wide nocase
        $guid_658C8B7F_3664_4A95_9572_A3E5871DFC06_bin = { 7F 8B 8C 65 64 36 95 4A 95 72 A3 E5 87 1D FC 06 }

        // PEASS - Privilege Escalation Awesome Scripts SUITE
        // https://github.com/carlospolop/PEASS-ng
        $guid_66AA4619_4D0F_4226_9D96_298870E9BB50_str = "66AA4619-4D0F-4226-9D96-298870E9BB50" ascii wide nocase
        $guid_66AA4619_4D0F_4226_9D96_298870E9BB50_bin = { 19 46 AA 66 0F 4D 26 42 9D 96 29 88 70 E9 BB 50 }

        // Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading
        // https://github.com/Flangvik/SharpDllProxy
        $guid_676E89F3_4785_477A_BA1C_B30340F598D5_str = "676E89F3-4785-477A-BA1C-B30340F598D5" ascii wide nocase
        $guid_676E89F3_4785_477A_BA1C_B30340F598D5_bin = { F3 89 6E 67 85 47 7A 47 BA 1C B3 03 40 F5 98 D5 }

        // Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // https://github.com/Leo4j/Amnesiac
        $guid_678ce24e_70c4_47b1_b595_ca0835ba35d9_str = "678ce24e-70c4-47b1-b595-ca0835ba35d9" ascii wide nocase
        $guid_678ce24e_70c4_47b1_b595_ca0835ba35d9_bin = { 4E E2 8C 67 C4 70 B1 47 B5 95 CA 08 35 BA 35 D9 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_6A2BA6F7_3399_4890_9453_2D5BE8EEBBA9_str = "6A2BA6F7-3399-4890-9453-2D5BE8EEBBA9" ascii wide nocase
        $guid_6A2BA6F7_3399_4890_9453_2D5BE8EEBBA9_bin = { F7 A6 2B 6A 99 33 90 48 94 53 2D 5B E8 EE BB A9 }

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_6A3F2F04_3E48_4E21_9AB8_0CA0998A2D01_str = "6A3F2F04-3E48-4E21-9AB8-0CA0998A2D01" ascii wide nocase
        $guid_6A3F2F04_3E48_4E21_9AB8_0CA0998A2D01_bin = { 04 2F 3F 6A 48 3E 21 4E 9A B8 0C A0 99 8A 2D 01 }

        // collection of post-exploitation tools to gather credentials from various password managers
        // https://github.com/Slowerzs/ThievingFox
        $guid_6A5942A4_9086_408E_A9B4_05ABC34BFD58_str = "6A5942A4-9086-408E-A9B4-05ABC34BFD58" ascii wide nocase
        $guid_6A5942A4_9086_408E_A9B4_05ABC34BFD58_bin = { A4 42 59 6A 86 90 8E 40 A9 B4 05 AB C3 4B FD 58 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_6AA4E392_AAAF_4408_B550_85863DD4BAAF_str = "6AA4E392-AAAF-4408-B550-85863DD4BAAF" ascii wide nocase
        $guid_6AA4E392_AAAF_4408_B550_85863DD4BAAF_bin = { 92 E3 A4 6A AF AA 08 44 B5 50 85 86 3D D4 BA AF }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_6AA4E392_AAAF_4408_B550_85863DF3BAAF_str = "6AA4E392-AAAF-4408-B550-85863DF3BAAF" ascii wide nocase
        $guid_6AA4E392_AAAF_4408_B550_85863DF3BAAF_bin = { 92 E3 A4 6A AF AA 08 44 B5 50 85 86 3D F3 BA AF }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_6C0942A1_C852_40F4_95F9_953510BD102D_str = "6C0942A1-C852-40F4-95F9-953510BD102D" ascii wide nocase
        $guid_6C0942A1_C852_40F4_95F9_953510BD102D_bin = { A1 42 09 6C 52 C8 F4 40 95 F9 95 35 10 BD 10 2D }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_6C8ECB51_EECE_49C3_89EC_CB0AAECCFF7E_str = "6C8ECB51-EECE-49C3-89EC-CB0AAECCFF7E" ascii wide nocase
        $guid_6C8ECB51_EECE_49C3_89EC_CB0AAECCFF7E_bin = { 51 CB 8E 6C CE EE C3 49 89 EC CB 0A AE CC FF 7E }

        // Indirect Dynamic Syscall SSN + Syscall address sorting via Modified TartarusGate approach + Remote Process Injection via APC Early Bird + Spawns a sacrificial Process as target process + (ACG+BlockDll) mitigation policy on spawned process + PPID spoofing (Emotet method) + Api resolving from TIB + API hashing
        // https://github.com/reveng007/DarkWidow
        $guid_6C9CF6A0_C098_4341_8DD1_2FCBA9594067_str = "6C9CF6A0-C098-4341-8DD1-2FCBA9594067" ascii wide nocase
        $guid_6C9CF6A0_C098_4341_8DD1_2FCBA9594067_bin = { A0 F6 9C 6C 98 C0 41 43 8D D1 2F CB A9 59 40 67 }

        // PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // https://github.com/PowerShellMafia/PowerSploit
        $guid_6CAFC0C6_A428_4D30_A9F9_700E829FEA51_str = "6CAFC0C6-A428-4D30-A9F9-700E829FEA51" ascii wide nocase
        $guid_6CAFC0C6_A428_4D30_A9F9_700E829FEA51_bin = { C6 C0 AF 6C 28 A4 30 4D A9 F9 70 0E 82 9F EA 51 }

        // An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // https://github.com/amjcyber/pwnlook
        $guid_6D663511_76E4_4D74_9B3E_191E1471C4EF_str = "6D663511-76E4-4D74-9B3E-191E1471C4EF" ascii wide nocase
        $guid_6D663511_76E4_4D74_9B3E_191E1471C4EF_bin = { 11 35 66 6D E4 76 74 4D 9B 3E 19 1E 14 71 C4 EF }

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_6DD22880_DAC5_4B4D_9C91_8C35CC7B8180_str = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" ascii wide nocase
        $guid_6DD22880_DAC5_4B4D_9C91_8C35CC7B8180_bin = { 80 28 D2 6D C5 DA 4D 4B 9C 91 8C 35 CC 7B 81 80 }

        // walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // https://github.com/malcomvetter/Periscope
        $guid_6DE0DE7E_A81D_4194_B36A_3E67283FCABE_str = "6DE0DE7E-A81D-4194-B36A-3E67283FCABE" ascii wide nocase
        $guid_6DE0DE7E_A81D_4194_B36A_3E67283FCABE_bin = { 7E DE E0 6D 1D A8 94 41 B3 6A 3E 67 28 3F CA BE }

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_6E0D8D5C_7B88_4C77_A347_34F8B0FD2D75_str = "6E0D8D5C-7B88-4C77-A347-34F8B0FD2D75" ascii wide nocase
        $guid_6E0D8D5C_7B88_4C77_A347_34F8B0FD2D75_bin = { 5C 8D 0D 6E 88 7B 77 4C A3 47 34 F8 B0 FD 2D 75 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_6E25C93C_0985_4D6E_A4C3_89D10F4F4F5F_str = "6E25C93C-0985-4D6E-A4C3-89D10F4F4F5F" ascii wide nocase
        $guid_6E25C93C_0985_4D6E_A4C3_89D10F4F4F5F_bin = { 3C C9 25 6E 85 09 6E 4D A4 C3 89 D1 0F 4F 4F 5F }

        //  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // https://github.com/rvrsh3ll/SharpSSDP
        $guid_6E383DE4_DE89_4247_A41A_79DB1DC03AAA_str = "6E383DE4-DE89-4247-A41A-79DB1DC03AAA" ascii wide nocase
        $guid_6E383DE4_DE89_4247_A41A_79DB1DC03AAA_bin = { E4 3D 38 6E 89 DE 47 42 A4 1A 79 DB 1D C0 3A AA }

        // LiquidSnake is a tool that allows operators to perform fileless Lateral Movement using WMI Event Subscriptions and GadgetToJScript
        // https://github.com/RiccardoAncarani/LiquidSnake
        $guid_6e7645c4_32c5_4fe3_aabf_e94c2f4370e7_str = "6e7645c4-32c5-4fe3-aabf-e94c2f4370e7" ascii wide nocase
        $guid_6e7645c4_32c5_4fe3_aabf_e94c2f4370e7_bin = { C4 45 76 6E C5 32 E3 4F AA BF E9 4C 2F 43 70 E7 }

        // Dump the memory of a PPL with a userland exploit
        // https://github.com/itm4n/PPLdump
        $guid_6E8D2C12_255B_403C_9EF3_8A097D374DB2_str = "6E8D2C12-255B-403C-9EF3-8A097D374DB2" ascii wide nocase
        $guid_6E8D2C12_255B_403C_9EF3_8A097D374DB2_bin = { 12 2C 8D 6E 5B 25 3C 40 9E F3 8A 09 7D 37 4D B2 }

        // Executes PowerShell from an unmanaged process
        // https://github.com/leechristensen/UnmanagedPowerShell
        $guid_6EB55FE6_C11C_453B_8B32_22B689B6B3E2_str = "6EB55FE6-C11C-453B-8B32-22B689B6B3E2" ascii wide nocase
        $guid_6EB55FE6_C11C_453B_8B32_22B689B6B3E2_bin = { E6 5F B5 6E 1C C1 3B 45 8B 32 22 B6 89 B6 B3 E2 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_6EFFA73B_AB71_4594_AEFF_1C127387A9CE_str = "6EFFA73B-AB71-4594-AEFF-1C127387A9CE" ascii wide nocase
        $guid_6EFFA73B_AB71_4594_AEFF_1C127387A9CE_bin = { 3B A7 FF 6E 71 AB 94 45 AE FF 1C 12 73 87 A9 CE }

        // Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // https://github.com/daem0nc0re/PrivFu
        $guid_6F99CB40_8FEF_4B63_A35D_9CEEC71F7B5F_str = "6F99CB40-8FEF-4B63-A35D-9CEEC71F7B5F" ascii wide nocase
        $guid_6F99CB40_8FEF_4B63_A35D_9CEEC71F7B5F_bin = { 40 CB 99 6F EF 8F 63 4B A3 5D 9C EE C7 1F 7B 5F }

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_6FC09BDB_365F_4691_BBD9_CB7F69C9527A_str = "6FC09BDB-365F-4691-BBD9-CB7F69C9527A" ascii wide nocase
        $guid_6FC09BDB_365F_4691_BBD9_CB7F69C9527A_bin = { DB 9B C0 6F 5F 36 91 46 BB D9 CB 7F 69 C9 52 7A }

        // Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // https://github.com/codesiddhant/Jasmin-Ransomware
        $guid_6FF9974C_B3C6_4EEA_8472_22BE6BD6F5CD_str = "6FF9974C-B3C6-4EEA-8472-22BE6BD6F5CD" ascii wide nocase
        $guid_6FF9974C_B3C6_4EEA_8472_22BE6BD6F5CD_bin = { 4C 97 F9 6F C6 B3 EA 4E 84 72 22 BE 6B D6 F5 CD }

        // Create a minidump of the LSASS process from memory
        // https://github.com/b4rtik/SharpMiniDump
        $guid_6FFCCF81_6C3C_4D3F_B15F_35A86D0B497F_str = "6FFCCF81-6C3C-4D3F-B15F-35A86D0B497F" ascii wide nocase
        $guid_6FFCCF81_6C3C_4D3F_B15F_35A86D0B497F_bin = { 81 CF FC 6F 3C 6C 3F 4D B1 5F 35 A8 6D 0B 49 7F }

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_70527328_DCEC_4BA7_9958_B5BC3E48CE99_str = "70527328-DCEC-4BA7-9958-B5BC3E48CE99" ascii wide nocase
        $guid_70527328_DCEC_4BA7_9958_B5BC3E48CE99_bin = { 28 73 52 70 EC DC A7 4B 99 58 B5 BC 3E 48 CE 99 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_70795D10_8ADF_4A4D_A584_9AB1BBF40D4B_str = "70795D10-8ADF-4A4D-A584-9AB1BBF40D4B" ascii wide nocase
        $guid_70795D10_8ADF_4A4D_A584_9AB1BBF40D4B_bin = { 10 5D 79 70 DF 8A 4D 4A A5 84 9A B1 BB F4 0D 4B }

        // A small tool that can list the named pipes bound on a remote system.
        // https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $guid_70BCFFDB_AE25_4BEA_BF0E_09DF06B7DBC4_str = "70BCFFDB-AE25-4BEA-BF0E-09DF06B7DBC4" ascii wide nocase
        $guid_70BCFFDB_AE25_4BEA_BF0E_09DF06B7DBC4_bin = { DB FF BC 70 25 AE EA 4B BF 0E 09 DF 06 B7 DB C4 }

        // Cobalt Strike Beacon Object File (BOF) Conversion of the Mockingjay Process Injection Technique
        // https://github.com/ewby/Mockingjay_BOF
        $guid_713724C3_2367_49FA_B03F_AB4B336FB405_str = "713724C3-2367-49FA-B03F-AB4B336FB405" ascii wide nocase
        $guid_713724C3_2367_49FA_B03F_AB4B336FB405_bin = { C3 24 37 71 67 23 FA 49 B0 3F AB 4B 33 6F B4 05 }

        // Remote keylogger for Windows written in C++
        // https://github.com/shehzade/peeping-tom
        $guid_71bda8ea_08bc_4ab1_9b40_614b167beb64_str = "71bda8ea-08bc-4ab1-9b40-614b167beb64" ascii wide nocase
        $guid_71bda8ea_08bc_4ab1_9b40_614b167beb64_bin = { EA A8 BD 71 BC 08 B1 4A 9B 40 61 4B 16 7B EB 64 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7219BFA2_5DA4_4608_A3FC_643B7E87E77A_str = "7219BFA2-5DA4-4608-A3FC-643B7E87E77A" ascii wide nocase
        $guid_7219BFA2_5DA4_4608_A3FC_643B7E87E77A_bin = { A2 BF 19 72 A4 5D 08 46 A3 FC 64 3B 7E 87 E7 7A }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7223F9B2_17A2_432B_ADAC_51B1E35681DB_str = "7223F9B2-17A2-432B-ADAC-51B1E35681DB" ascii wide nocase
        $guid_7223F9B2_17A2_432B_ADAC_51B1E35681DB_bin = { B2 F9 23 72 A2 17 2B 43 AD AC 51 B1 E3 56 81 DB }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_7271AFD1_10F6_4589_95B7_3ABF98E7B2CA_str = "7271AFD1-10F6-4589-95B7-3ABF98E7B2CA" ascii wide nocase
        $guid_7271AFD1_10F6_4589_95B7_3ABF98E7B2CA_bin = { D1 AF 71 72 F6 10 89 45 95 B7 3A BF 98 E7 B2 CA }

        // A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // https://github.com/keowu/BadRentdrv2
        $guid_727a1d04_70f4_4148_9120_d06510a62a9a_str = "727a1d04-70f4-4148-9120-d06510a62a9a" ascii wide nocase
        $guid_727a1d04_70f4_4148_9120_d06510a62a9a_bin = { 04 1D 7A 72 F4 70 48 41 91 20 D0 65 10 A6 2A 9A }

        // walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // https://github.com/malcomvetter/Periscope
        $guid_72DCE01A_B6EC_4AC3_A98B_D5C44D532626_str = "72DCE01A-B6EC-4AC3-A98B-D5C44D532626" ascii wide nocase
        $guid_72DCE01A_B6EC_4AC3_A98B_D5C44D532626_bin = { 1A E0 DC 72 EC B6 C3 4A A9 8B D5 C4 4D 53 26 26 }

        // BOF for Kerberos abuse (an implementation of some important features of the Rubeus)
        // https://github.com/RalfHacker/Kerbeus-BOF
        $guid_732211ae_4891_40d3_b2b6_85ebd6f5ffff_str = "732211ae-4891-40d3-b2b6-85ebd6f5ffff" ascii wide nocase
        $guid_732211ae_4891_40d3_b2b6_85ebd6f5ffff_bin = { AE 11 22 73 91 48 D3 40 B2 B6 85 EB D6 F5 FF FF }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_73226E13_1701_424E_A4F2_3E4D575A1DD0_str = "73226E13-1701-424E-A4F2-3E4D575A1DD0" ascii wide nocase
        $guid_73226E13_1701_424E_A4F2_3E4D575A1DD0_bin = { 13 6E 22 73 01 17 4E 42 A4 F2 3E 4D 57 5A 1D D0 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_733C37D8_858F_44EE_9D17_790F7DE9C040_str = "733C37D8-858F-44EE-9D17-790F7DE9C040" ascii wide nocase
        $guid_733C37D8_858F_44EE_9D17_790F7DE9C040_bin = { D8 37 3C 73 8F 85 EE 44 9D 17 79 0F 7D E9 C0 40 }

        // Shellcode runner framework for application whitelisting bypasses and DLL side-loading
        // https://github.com/mandiant/DueDLLigence
        $guid_73948912_CEBD_48ED_85E2_85FCD1D4F560_str = "73948912-CEBD-48ED-85E2-85FCD1D4F560" ascii wide nocase
        $guid_73948912_CEBD_48ED_85E2_85FCD1D4F560_bin = { 12 89 94 73 BD CE ED 48 85 E2 85 FC D1 D4 F5 60 }

        // A C# implementation of RDPThief to steal credentials from RDP
        // https://github.com/passthehashbrowns/SharpRDPThief
        $guid_73B2C22B_C020_45B7_BF61_B48F49A2693F_str = "73B2C22B-C020-45B7-BF61-B48F49A2693F" ascii wide nocase
        $guid_73B2C22B_C020_45B7_BF61_B48F49A2693F_bin = { 2B C2 B2 73 20 C0 B7 45 BF 61 B4 8F 49 A2 69 3F }

        // VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // https://github.com/humphd/VncSharp
        $guid_73e83646_1d53_4dec_950a_a48559e438e8_str = "73e83646-1d53-4dec-950a-a48559e438e8" ascii wide nocase
        $guid_73e83646_1d53_4dec_950a_a48559e438e8_bin = { 46 36 E8 73 53 1D EC 4D 95 0A A4 85 59 E4 38 E8 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_73ECE052_4218_465D_AA2E_A2D03448BEDD_str = "73ECE052-4218-465D-AA2E-A2D03448BEDD" ascii wide nocase
        $guid_73ECE052_4218_465D_AA2E_A2D03448BEDD_bin = { 52 E0 EC 73 18 42 5D 46 AA 2E A2 D0 34 48 BE DD }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_73EF1630_1208_43C5_9E3F_19A2923875C5_str = "73EF1630-1208-43C5-9E3F-19A2923875C5" ascii wide nocase
        $guid_73EF1630_1208_43C5_9E3F_19A2923875C5_bin = { 30 16 EF 73 08 12 C5 43 9E 3F 19 A2 92 38 75 C5 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_73F11EE8_F565_479E_8366_BD74EE467CE8_str = "73F11EE8-F565-479E-8366-BD74EE467CE8" ascii wide nocase
        $guid_73F11EE8_F565_479E_8366_BD74EE467CE8_bin = { E8 1E F1 73 65 F5 9E 47 83 66 BD 74 EE 46 7C E8 }

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_758DB128_9123_4E1B_A6C3_47323714123A_str = "758DB128-9123-4E1B-A6C3-47323714123A" ascii wide nocase
        $guid_758DB128_9123_4E1B_A6C3_47323714123A_bin = { 28 B1 8D 75 23 91 1B 4E A6 C3 47 32 37 14 12 3A }

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_758DB129_9123_4E1B_A6C3_47323714123A_str = "758DB129-9123-4E1B-A6C3-47323714123A" ascii wide nocase
        $guid_758DB129_9123_4E1B_A6C3_47323714123A_bin = { 29 B1 8D 75 23 91 1B 4E A6 C3 47 32 37 14 12 3A }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_75E5F9A0_8D69_4426_9F16_4A65E941974D_str = "75E5F9A0-8D69-4426-9F16-4A65E941974D" ascii wide nocase
        $guid_75E5F9A0_8D69_4426_9F16_4A65E941974D_bin = { A0 F9 E5 75 69 8D 26 44 9F 16 4A 65 E9 41 97 4D }

        // perform S4U logon with SeTcbPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_7607CC54_D49D_4004_8B20_15555D58C842_str = "7607CC54-D49D-4004-8B20-15555D58C842" ascii wide nocase
        $guid_7607CC54_D49D_4004_8B20_15555D58C842_bin = { 54 CC 07 76 9D D4 04 40 8B 20 15 55 5D 58 C8 42 }

        // Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // https://github.com/binderlabs/DirCreate2System
        $guid_765C5755_DBE9_4AB5_9427_921D0E46F9F0_str = "765C5755-DBE9-4AB5-9427-921D0E46F9F0" ascii wide nocase
        $guid_765C5755_DBE9_4AB5_9427_921D0E46F9F0_bin = { 55 57 5C 76 E9 DB B5 4A 94 27 92 1D 0E 46 F9 F0 }

        // AutoHotkey - macro-creation and automation-oriented scripting utility for Windows
        // https://github.com/AutoHotkey/AutoHotkey
        $guid_76EFDEE3_81CF_4ADA_94DC_EA5509FF6FFC_str = "76EFDEE3-81CF-4ADA-94DC-EA5509FF6FFC" ascii wide nocase
        $guid_76EFDEE3_81CF_4ADA_94DC_EA5509FF6FFC_bin = { E3 DE EF 76 CF 81 DA 4A 94 DC EA 55 09 FF 6F FC }

        // Basic password spraying tool for internal tests and red teaming
        // https://github.com/HunnicCyber/SharpDomainSpray
        $guid_76FFA92B_429B_4865_970D_4E7678AC34EA_str = "76FFA92B-429B-4865-970D-4E7678AC34EA" ascii wide nocase
        $guid_76FFA92B_429B_4865_970D_4E7678AC34EA_bin = { 2B A9 FF 76 9B 42 65 48 97 0D 4E 76 78 AC 34 EA }

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_7760248F_9247_4206_BE42_A6952AA46DA2_str = "7760248F-9247-4206-BE42-A6952AA46DA2" ascii wide nocase
        $guid_7760248F_9247_4206_BE42_A6952AA46DA2_bin = { 8F 24 60 77 47 92 06 42 BE 42 A6 95 2A A4 6D A2 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_77612014_2E37_4E17_AAFE_9AD4F08B4263_str = "77612014-2E37-4E17-AAFE-9AD4F08B4263" ascii wide nocase
        $guid_77612014_2E37_4E17_AAFE_9AD4F08B4263_bin = { 14 20 61 77 37 2E 17 4E AA FE 9A D4 F0 8B 42 63 }

        // Open-Source Remote Administration Tool For Windows C# (RAT)
        // https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $guid_7767C300_5FD5_4A5D_9D4C_59559CCE48A3_str = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" ascii wide nocase
        $guid_7767C300_5FD5_4A5D_9D4C_59559CCE48A3_bin = { 00 C3 67 77 D5 5F 5D 4A 9D 4C 59 55 9C CE 48 A3 }

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_7777E837_E7A3_481B_8BD2_4C76F639ECFC_str = "7777E837-E7A3-481B-8BD2-4C76F639ECFC" ascii wide nocase
        $guid_7777E837_E7A3_481B_8BD2_4C76F639ECFC_bin = { 37 E8 77 77 A3 E7 1B 48 8B D2 4C 76 F6 39 EC FC }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_77F955C3_4910_49EA_9CD4_CBF5AD9C071A_str = "77F955C3-4910-49EA-9CD4-CBF5AD9C071A" ascii wide nocase
        $guid_77F955C3_4910_49EA_9CD4_CBF5AD9C071A_bin = { C3 55 F9 77 10 49 EA 49 9C D4 CB F5 AD 9C 07 1A }

        // Timestomp Tool to flatten MAC times with a specific timestamp
        // https://github.com/ZephrFish/Stompy
        $guid_784F8029_4D72_4363_9638_5A8D11545494_str = "784F8029-4D72-4363-9638-5A8D11545494" ascii wide nocase
        $guid_784F8029_4D72_4363_9638_5A8D11545494_bin = { 29 80 4F 78 72 4D 63 43 96 38 5A 8D 11 54 54 94 }

        // Undetectable Payload Generator Tool
        // https://github.com/1y0n/AV_Evasion_Tool
        $guid_7898617D_08D2_4297_ADFE_5EDD5C1B828B_str = "7898617D-08D2-4297-ADFE-5EDD5C1B828B" ascii wide nocase
        $guid_7898617D_08D2_4297_ADFE_5EDD5C1B828B_bin = { 7D 61 98 78 D2 08 97 42 AD FE 5E DD 5C 1B 82 8B }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_78BB6D02_6E02_4933_89DC_4AD8EE0B303F_str = "78BB6D02-6E02-4933-89DC-4AD8EE0B303F" ascii wide nocase
        $guid_78BB6D02_6E02_4933_89DC_4AD8EE0B303F_bin = { 02 6D BB 78 02 6E 33 49 89 DC 4A D8 EE 0B 30 3F }

        // Jasmin Ransomware is an advanced red team tool (WannaCry Clone) used for simulating real ransomware attacks
        // https://github.com/codesiddhant/Jasmin-Ransomware
        $guid_78C76961_8249_4EFE_9DE2_B6EF15A187F7_str = "78C76961-8249-4EFE-9DE2-B6EF15A187F7" ascii wide nocase
        $guid_78C76961_8249_4EFE_9DE2_B6EF15A187F7_bin = { 61 69 C7 78 49 82 FE 4E 9D E2 B6 EF 15 A1 87 F7 }

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_78DE9716_84E8_4469_A5AE_F3E43181C28B_str = "78DE9716-84E8-4469-A5AE-F3E43181C28B" ascii wide nocase
        $guid_78DE9716_84E8_4469_A5AE_F3E43181C28B_bin = { 16 97 DE 78 E8 84 69 44 A5 AE F3 E4 31 81 C2 8B }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_78EB3006_81B0_4C13_9B80_E91766874A57_str = "78EB3006-81B0-4C13-9B80-E91766874A57" ascii wide nocase
        $guid_78EB3006_81B0_4C13_9B80_E91766874A57_bin = { 06 30 EB 78 B0 81 13 4C 9B 80 E9 17 66 87 4A 57 }

        // A C# implementation of dumping credentials from Windows Credential Manager
        // https://github.com/leftp/BackupCreds
        $guid_7943C5FF_C219_4E0B_992E_0ECDEB2681F3_str = "7943C5FF-C219-4E0B-992E-0ECDEB2681F3" ascii wide nocase
        $guid_7943C5FF_C219_4E0B_992E_0ECDEB2681F3_bin = { FF C5 43 79 19 C2 0B 4E 99 2E 0E CD EB 26 81 F3 }

        // control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // https://gitlab.com/KevinJClark/badrats
        $guid_79520C3A_4931_46EB_92D7_334DA7FC9013_str = "79520C3A-4931-46EB-92D7-334DA7FC9013" ascii wide nocase
        $guid_79520C3A_4931_46EB_92D7_334DA7FC9013_bin = { 3A 0C 52 79 31 49 EB 46 92 D7 33 4D A7 FC 90 13 }

        // SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
        // https://github.com/GhostPack/SharpDump
        $guid_79C9BBA3_A0EA_431C_866C_77004802D8A0_str = "79C9BBA3-A0EA-431C-866C-77004802D8A0" ascii wide nocase
        $guid_79C9BBA3_A0EA_431C_866C_77004802D8A0_bin = { A3 BB C9 79 EA A0 1C 43 86 6C 77 00 48 02 D8 A0 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_79D3788D_683D_4799_94B7_00360F08145B_str = "79D3788D-683D-4799-94B7-00360F08145B" ascii wide nocase
        $guid_79D3788D_683D_4799_94B7_00360F08145B_bin = { 8D 78 D3 79 3D 68 99 47 94 B7 00 36 0F 08 14 5B }

        // Abuses the Windows containers framework to bypass EDRs.
        // https://github.com/deepinstinct/ContainYourself
        $guid_79F54747_048D_4FD6_AEF4_7B098F923FD8_str = "79F54747-048D-4FD6-AEF4-7B098F923FD8" ascii wide nocase
        $guid_79F54747_048D_4FD6_AEF4_7B098F923FD8_bin = { 47 47 F5 79 8D 04 D6 4F AE F4 7B 09 8F 92 3F D8 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7A58EE54_7F2E_4C2F_B41E_19DD0D1629F1_str = "7A58EE54-7F2E-4C2F-B41E-19DD0D1629F1" ascii wide nocase
        $guid_7A58EE54_7F2E_4C2F_B41E_19DD0D1629F1_bin = { 54 EE 58 7A 2E 7F 2F 4C B4 1E 19 DD 0D 16 29 F1 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7A6CEC00_4A6C_45E0_A25D_3CAB2F436EA6_str = "7A6CEC00-4A6C-45E0-A25D-3CAB2F436EA6" ascii wide nocase
        $guid_7A6CEC00_4A6C_45E0_A25D_3CAB2F436EA6_bin = { 00 EC 6C 7A 6C 4A E0 45 A2 5D 3C AB 2F 43 6E A6 }

        // A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // https://github.com/ihamburglar/fgdump
        $guid_7A87DEAE_7B94_4986_9294_BD69B12A9732_str = "7A87DEAE-7B94-4986-9294-BD69B12A9732" ascii wide nocase
        $guid_7A87DEAE_7B94_4986_9294_BD69B12A9732_bin = { AE DE 87 7A 94 7B 86 49 92 94 BD 69 B1 2A 97 32 }

        // Injects a DLL into a suspended process running as SYSTEM via the OfficeClickToRun service for privilege escalation - Shim Injector: Injects a DLL into a process by modifying shim data in memory without creating or registering new SDB files to evade detection.
        // https://github.com/deepinstinct/ShimMe
        $guid_7afe06b8_59cc_41d2_9d75_65473ea93117_str = "7afe06b8-59cc-41d2-9d75-65473ea93117" ascii wide nocase
        $guid_7afe06b8_59cc_41d2_9d75_65473ea93117_bin = { B8 06 FE 7A CC 59 D2 41 9D 75 65 47 3E A9 31 17 }

        // Persistence by writing/reading shellcode from Event Log
        // https://github.com/improsec/SharpEventPersist
        $guid_7B4D3810_4A77_44A1_8546_779ACF02D083_str = "7B4D3810-4A77-44A1-8546-779ACF02D083" ascii wide nocase
        $guid_7B4D3810_4A77_44A1_8546_779ACF02D083_bin = { 10 38 4D 7B 77 4A A1 44 85 46 77 9A CF 02 D0 83 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7BCD7440_845C_417B_8C2F_AA89D3AE8FD0_str = "7BCD7440-845C-417B-8C2F-AA89D3AE8FD0" ascii wide nocase
        $guid_7BCD7440_845C_417B_8C2F_AA89D3AE8FD0_bin = { 40 74 CD 7B 5C 84 7B 41 8C 2F AA 89 D3 AE 8F D0 }

        // DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // https://github.com/deepinstinct/DCOMUploadExec
        $guid_7bf6b6be_a29f_440a_9962_9fabc5d9665a_str = "7bf6b6be-a29f-440a-9962-9fabc5d9665a" ascii wide nocase
        $guid_7bf6b6be_a29f_440a_9962_9fabc5d9665a_bin = { BE B6 F6 7B 9F A2 0A 44 99 62 9F AB C5 D9 66 5A }

        // An open-source windows defender manager. Now you can disable windows defender permanently
        // https://github.com/pgkt04/defender-control
        $guid_7c2c0aec_7b9d_4104_99fa_1844d609452c_str = "7c2c0aec-7b9d-4104-99fa-1844d609452c" ascii wide nocase
        $guid_7c2c0aec_7b9d_4104_99fa_1844d609452c_bin = { EC 0A 2C 7C 9D 7B 04 41 99 FA 18 44 D6 09 45 2C }

        // allowing the execution of Powershell functionality without the use of Powershell.exe
        // https://github.com/PowerShellEmpire/PowerTools
        $guid_7C3D26E5_0A61_479A_AFAC_D34F2659F301_str = "7C3D26E5-0A61-479A-AFAC-D34F2659F301" ascii wide nocase
        $guid_7C3D26E5_0A61_479A_AFAC_D34F2659F301_bin = { E5 26 3D 7C 61 0A 9A 47 AF AC D3 4F 26 59 F3 01 }

        // Complete exploit works on vulnerable Windows 11 22H2 systems CVE-2023-36802 Local Privilege Escalation POC
        // https://github.com/chompie1337/Windows_MSKSSRV_LPE_CVE-2023-36802
        $guid_7C5C471B_9630_4DF5_A099_405D86553ECA_str = "7C5C471B-9630-4DF5-A099-405D86553ECA" ascii wide nocase
        $guid_7C5C471B_9630_4DF5_A099_405D86553ECA_bin = { 1B 47 5C 7C 30 96 F5 4D A0 99 40 5D 86 55 3E CA }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_7C6D1CCD_D4DF_426A_B5D6_A6B5F13D0091_str = "7C6D1CCD-D4DF-426A-B5D6-A6B5F13D0091" ascii wide nocase
        $guid_7C6D1CCD_D4DF_426A_B5D6_A6B5F13D0091_bin = { CD 1C 6D 7C DF D4 6A 42 B5 D6 A6 B5 F1 3D 00 91 }

        // Hide your P/Invoke signatures through other people's signed assemblies
        // https://github.com/MzHmO/Parasite-Invoke
        $guid_7CEC7793_3E22_455B_9E88_94B8D1A8F78D_str = "7CEC7793-3E22-455B-9E88-94B8D1A8F78D" ascii wide nocase
        $guid_7CEC7793_3E22_455B_9E88_94B8D1A8F78D_bin = { 93 77 EC 7C 22 3E 5B 45 9E 88 94 B8 D1 A8 F7 8D }

        // perform the RottenPotato attack and get a handle to a privileged token
        // https://github.com/breenmachine/RottenPotatoNG
        $guid_7E1BCC8E_F61C_4728_BB8A_28FB42928256_str = "7E1BCC8E-F61C-4728-BB8A-28FB42928256" ascii wide nocase
        $guid_7E1BCC8E_F61C_4728_BB8A_28FB42928256_bin = { 8E CC 1B 7E 1C F6 28 47 BB 8A 28 FB 42 92 82 56 }

        // EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // https://github.com/wavestone-cdt/EDRSandblast
        $guid_7E3E2ECE_D1EB_43C6_8C83_B52B7571954B_str = "7E3E2ECE-D1EB-43C6-8C83-B52B7571954B" ascii wide nocase
        $guid_7E3E2ECE_D1EB_43C6_8C83_B52B7571954B_bin = { CE 2E 3E 7E EB D1 C6 43 8C 83 B5 2B 75 71 95 4B }

        // A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // https://github.com/ShorSec/ShadowSpray
        $guid_7E47D586_DDC6_4382_848C_5CF0798084E1_str = "7E47D586-DDC6-4382-848C-5CF0798084E1" ascii wide nocase
        $guid_7E47D586_DDC6_4382_848C_5CF0798084E1_bin = { 86 D5 47 7E C6 DD 82 43 84 8C 5C F0 79 80 84 E1 }

        // Crassus Windows privilege escalation discovery tool
        // https://github.com/vu-ls/Crassus
        $guid_7E9729AA_4CF2_4D0A_8183_7FB7CE7A5B1A_str = "7E9729AA-4CF2-4D0A-8183-7FB7CE7A5B1A" ascii wide nocase
        $guid_7E9729AA_4CF2_4D0A_8183_7FB7CE7A5B1A_bin = { AA 29 97 7E F2 4C 0A 4D 81 83 7F B7 CE 7A 5B 1A }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_7EAE7E78_ED95_4CAB_B3B3_231B41BB5AA0_str = "7EAE7E78-ED95-4CAB-B3B3-231B41BB5AA0" ascii wide nocase
        $guid_7EAE7E78_ED95_4CAB_B3B3_231B41BB5AA0_bin = { 78 7E AE 7E 95 ED AB 4C B3 B3 23 1B 41 BB 5A A0 }

        // Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // https://github.com/binderlabs/DirCreate2System
        $guid_7EE536AE_6C1D_4881_88F7_37C8F2A0CA50_str = "7EE536AE-6C1D-4881-88F7-37C8F2A0CA50" ascii wide nocase
        $guid_7EE536AE_6C1D_4881_88F7_37C8F2A0CA50_bin = { AE 36 E5 7E 1D 6C 81 48 88 F7 37 C8 F2 A0 CA 50 }

        // Bypass antivirus software to add users
        // https://github.com/TryA9ain/BypassAddUser
        $guid_7FDCF4E0_2E6A_43D5_80FB_0A1A40AB3D93_str = "7FDCF4E0-2E6A-43D5-80FB-0A1A40AB3D93" ascii wide nocase
        $guid_7FDCF4E0_2E6A_43D5_80FB_0A1A40AB3D93_bin = { E0 F4 DC 7F 6A 2E D5 43 80 FB 0A 1A 40 AB 3D 93 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_8026261f_ac68_4ccf_97b2_3b55b7d6684d_str = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" ascii wide nocase
        $guid_8026261f_ac68_4ccf_97b2_3b55b7d6684d_bin = { 1F 26 26 80 68 AC CF 4C 97 B2 3B 55 B7 D6 68 4D }

        // Malware RAT with keylogger - dll injection - C2 - Remote control
        // https://github.com/sin5678/gh0st
        $guid_80ABA1A7_0E3E_3DB2_8EB9_D4EE1C266504_str = "80ABA1A7-0E3E-3DB2-8EB9-D4EE1C266504" ascii wide nocase
        $guid_80ABA1A7_0E3E_3DB2_8EB9_D4EE1C266504_bin = { A7 A1 AB 80 3E 0E B2 3D 8E B9 D4 EE 1C 26 65 04 }

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_80BA63A4_7D41_40E9_A722_6DD58B28BF7E_str = "80BA63A4-7D41-40E9-A722-6DD58B28BF7E" ascii wide nocase
        $guid_80BA63A4_7D41_40E9_A722_6DD58B28BF7E_bin = { A4 63 BA 80 41 7D E9 40 A7 22 6D D5 8B 28 BF 7E }

        // enabling Recall in Windows 11 version 24H2 on unsupported devices
        // https://github.com/thebookisclosed/AmperageKit
        $guid_80C7245C_B926_4CEB_BA5B_5353736137A8_str = "80C7245C-B926-4CEB-BA5B-5353736137A8" ascii wide nocase
        $guid_80C7245C_B926_4CEB_BA5B_5353736137A8_bin = { 5C 24 C7 80 26 B9 EB 4C BA 5B 53 53 73 61 37 A8 }

        // Winsock accept() Backdoor Implant
        // https://github.com/EgeBalci/WSAAcceptBackdoor
        $guid_811683b1_e01c_4ef8_82d1_aa08293d3e7c_str = "811683b1-e01c-4ef8-82d1-aa08293d3e7c" ascii wide nocase
        $guid_811683b1_e01c_4ef8_82d1_aa08293d3e7c_bin = { B1 83 16 81 1C E0 F8 4E 82 D1 AA 08 29 3D 3E 7C }

        // Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // https://github.com/WithSecureLabs/physmem2profit
        $guid_814708C9_2320_42D2_A45F_31E42DA06A94_str = "814708C9-2320-42D2-A45F-31E42DA06A94" ascii wide nocase
        $guid_814708C9_2320_42D2_A45F_31E42DA06A94_bin = { C9 08 47 81 20 23 D2 42 A4 5F 31 E4 2D A0 6A 94 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_8169F27E_0314_44BB_8B89_DB3339FF51A3_str = "8169F27E-0314-44BB-8B89-DB3339FF51A3" ascii wide nocase
        $guid_8169F27E_0314_44BB_8B89_DB3339FF51A3_bin = { 7E F2 69 81 14 03 BB 44 8B 89 DB 33 39 FF 51 A3 }

        // Cross-platform multi-protocol VPN software abused by attackers
        // https://github.com/SoftEtherVPN/SoftEtherVPN
        $guid_81CA3EC4_026E_4D37_9889_828186BBB8C0_str = "81CA3EC4-026E-4D37-9889-828186BBB8C0" ascii wide nocase
        $guid_81CA3EC4_026E_4D37_9889_828186BBB8C0_bin = { C4 3E CA 81 6E 02 37 4D 98 89 82 81 86 BB B8 C0 }

        // Bypass EDR Hooks by patching NT API stub and resolving SSNs and syscall instructions at runtime
        // https://github.com/SaadAhla/UnhookingPatch
        $guid_81E60DC6_694E_4F51_88FA_6F481B9A4208_str = "81E60DC6-694E-4F51-88FA-6F481B9A4208" ascii wide nocase
        $guid_81E60DC6_694E_4F51_88FA_6F481B9A4208_bin = { C6 0D E6 81 4E 69 51 4F 88 FA 6F 48 1B 9A 42 08 }

        // Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // https://github.com/TheD1rkMtr/FilelessPELoader
        $guid_82277B35_D159_4B44_8D54_FB66EDD58D5C_str = "82277B35-D159-4B44-8D54-FB66EDD58D5C" ascii wide nocase
        $guid_82277B35_D159_4B44_8D54_FB66EDD58D5C_bin = { 35 7B 27 82 59 D1 44 4B 8D 54 FB 66 ED D5 8D 5C }

        // Microsoft Graph API post-exploitation toolkit
        // https://github.com/mlcsec/SharpGraphView
        $guid_825E2088_EC7C_4AB0_852A_4F1FEF178E37_str = "825E2088-EC7C-4AB0-852A-4F1FEF178E37" ascii wide nocase
        $guid_825E2088_EC7C_4AB0_852A_4F1FEF178E37_bin = { 88 20 5E 82 7C EC B0 4A 85 2A 4F 1F EF 17 8E 37 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_827D241C_6A9B_48B0_BA8C_F21EF2849405_str = "827D241C-6A9B-48B0-BA8C-F21EF2849405" ascii wide nocase
        $guid_827D241C_6A9B_48B0_BA8C_F21EF2849405_bin = { 1C 24 7D 82 9B 6A B0 48 BA 8C F2 1E F2 84 94 05 }

        // Patching signtool.exe to accept expired certificates for code-signing
        // https://github.com/hackerhouse-opensource/SignToolEx
        $guid_82B0EE92_347E_412F_8EA2_CBDE683EDA57_str = "82B0EE92-347E-412F-8EA2-CBDE683EDA57" ascii wide nocase
        $guid_82B0EE92_347E_412F_8EA2_CBDE683EDA57_bin = { 92 EE B0 82 7E 34 2F 41 8E A2 CB DE 68 3E DA 57 }

        // open source ransomware - many variant in the wild
        // https://github.com/goliate/hidden-tear
        $guid_82C19CBA_E318_4BB3_A408_5005EA083EC5_str = "82C19CBA-E318-4BB3-A408-5005EA083EC5" ascii wide nocase
        $guid_82C19CBA_E318_4BB3_A408_5005EA083EC5_bin = { BA 9C C1 82 18 E3 B3 4B A4 08 50 05 EA 08 3E C5 }

        // A red team tool that assists into extracting/dumping master credentials and/or entries from different password managers
        // https://github.com/efchatz/pandora
        $guid_82F417BE_49BF_44FF_9BBD_64FECEA181D7_str = "82F417BE-49BF-44FF-9BBD-64FECEA181D7" ascii wide nocase
        $guid_82F417BE_49BF_44FF_9BBD_64FECEA181D7_bin = { BE 17 F4 82 BF 49 FF 44 9B BD 64 FE CE A1 81 D7 }

        // Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // https://github.com/TheD1rkMtr/HeapCrypt
        $guid_83035080_7788_4EA3_82EE_6C06D2E6891F_str = "83035080-7788-4EA3-82EE-6C06D2E6891F" ascii wide nocase
        $guid_83035080_7788_4EA3_82EE_6C06D2E6891F_bin = { 80 50 03 83 88 77 A3 4E 82 EE 6C 06 D2 E6 89 1F }

        // in memory process dumper - uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output
        // https://github.com/riskydissonance/SafetyDump
        $guid_8347E81B_89FC_42A9_B22C_F59A6A572DEC_str = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii wide nocase
        $guid_8347E81B_89FC_42A9_B22C_F59A6A572DEC_bin = { 1B E8 47 83 FC 89 A9 42 B2 2C F5 9A 6A 57 2D EC }

        // abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // https://github.com/trustedsec/The_Shelf
        $guid_83DF0D0B_8FC6_4BCA_9982_4D26523515A2_str = "83DF0D0B-8FC6-4BCA-9982-4D26523515A2" ascii wide nocase
        $guid_83DF0D0B_8FC6_4BCA_9982_4D26523515A2_bin = { 0B 0D DF 83 C6 8F CA 4B 99 82 4D 26 52 35 15 A2 }

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_8425D05F_F3F4_4132_9BE1_BED752685333_str = "8425D05F-F3F4-4132-9BE1-BED752685333" ascii wide nocase
        $guid_8425D05F_F3F4_4132_9BE1_BED752685333_bin = { 5F D0 25 84 F4 F3 32 41 9B E1 BE D7 52 68 53 33 }

        // simple POC to show how to tunnel traffic through Azure Application Proxy
        // https://github.com/xpn/AppProxyC2
        $guid_8443F171_603C_499C_B6A6_F4F6910FD1D9_str = "8443F171-603C-499C-B6A6-F4F6910FD1D9" ascii wide nocase
        $guid_8443F171_603C_499C_B6A6_F4F6910FD1D9_bin = { 71 F1 43 84 3C 60 9C 49 B6 A6 F4 F6 91 0F D1 D9 }

        // generate obfuscated command-lines for common system-native executables
        // https://github.com/wietze/Invoke-ArgFuscator
        $guid_844d9edc_57ad_4fcc_9fd5_77a69d4bf569_str = "844d9edc-57ad-4fcc-9fd5-77a69d4bf569" ascii wide nocase
        $guid_844d9edc_57ad_4fcc_9fd5_77a69d4bf569_bin = { DC 9E 4D 84 AD 57 CC 4F 9F D5 77 A6 9D 4B F5 69 }

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_847D29FF_8BBC_4068_8BE1_D84B1089B3C0_str = "847D29FF-8BBC-4068-8BE1-D84B1089B3C0" ascii wide nocase
        $guid_847D29FF_8BBC_4068_8BE1_D84B1089B3C0_bin = { FF 29 7D 84 BC 8B 68 40 8B E1 D8 4B 10 89 B3 C0 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_8489A9CE_AB1A_4D8D_8824_D9E18B9945FE_str = "8489A9CE-AB1A-4D8D-8824-D9E18B9945FE" ascii wide nocase
        $guid_8489A9CE_AB1A_4D8D_8824_D9E18B9945FE_bin = { CE A9 89 84 1A AB 8D 4D 88 24 D9 E1 8B 99 45 FE }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_8493D0F0_CA01_4C5A_A6E3_C0F427966ABD_str = "8493D0F0-CA01-4C5A-A6E3-C0F427966ABD" ascii wide nocase
        $guid_8493D0F0_CA01_4C5A_A6E3_C0F427966ABD_bin = { F0 D0 93 84 01 CA 5A 4C A6 E3 C0 F4 27 96 6A BD }

        // Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // https://github.com/gitjdm/dumper2020
        $guid_84A7E50E_B0F0_4B3D_98CD_F32CDB1EB8CA_str = "84A7E50E-B0F0-4B3D-98CD-F32CDB1EB8CA" ascii wide nocase
        $guid_84A7E50E_B0F0_4B3D_98CD_F32CDB1EB8CA_bin = { 0E E5 A7 84 F0 B0 3D 4B 98 CD F3 2C DB 1E B8 CA }

        // A basic emulation of an "RPC Backdoor"
        // https://github.com/eladshamir/RPC-Backdoor
        $guid_8558952E_C76B_4976_949F_76A977DA7F8A_str = "8558952E-C76B-4976-949F-76A977DA7F8A" ascii wide nocase
        $guid_8558952E_C76B_4976_949F_76A977DA7F8A_bin = { 2E 95 58 85 6B C7 76 49 94 9F 76 A9 77 DA 7F 8A }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_862DA0DA_52E1_47CD_B9C2_46B106031B28_str = "862DA0DA-52E1-47CD-B9C2-46B106031B28" ascii wide nocase
        $guid_862DA0DA_52E1_47CD_B9C2_46B106031B28_bin = { DA A0 2D 86 E1 52 CD 47 B9 C2 46 B1 06 03 1B 28 }

        // Find vulnerabilities in AD Group Policy
        // https://github.com/Group3r/Group3r
        $guid_868A6C76_C903_4A94_96FD_A2C6BA75691C_str = "868A6C76-C903-4A94-96FD-A2C6BA75691C" ascii wide nocase
        $guid_868A6C76_C903_4A94_96FD_A2C6BA75691C_bin = { 76 6C 8A 86 03 C9 94 4A 96 FD A2 C6 BA 75 69 1C }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_86F8C733_F773_4AD8_9282_3F99953261FD_str = "86F8C733-F773-4AD8-9282-3F99953261FD" ascii wide nocase
        $guid_86F8C733_F773_4AD8_9282_3F99953261FD_bin = { 33 C7 F8 86 73 F7 D8 4A 92 82 3F 99 95 32 61 FD }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_86FC4B74_3B12_4C72_AA6C_084BF98E5E9A_str = "86FC4B74-3B12-4C72-AA6C-084BF98E5E9A" ascii wide nocase
        $guid_86FC4B74_3B12_4C72_AA6C_084BF98E5E9A_bin = { 74 4B FC 86 12 3B 72 4C AA 6C 08 4B F9 8E 5E 9A }

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_86FF6D04_208C_442F_B27C_E4255DD39402_str = "86FF6D04-208C-442F-B27C-E4255DD39402" ascii wide nocase
        $guid_86FF6D04_208C_442F_B27C_E4255DD39402_bin = { 04 6D FF 86 8C 20 2F 44 B2 7C E4 25 5D D3 94 02 }

        // Anti Forensics Tool For Red Teamers - Used For Erasing Some Footprints In The Post Exploitation Phase
        // https://github.com/PaulNorman01/Forensia
        $guid_87135ab4_4cf7_454c_8830_38eb3ede1241_str = "87135ab4-4cf7-454c-8830-38eb3ede1241" ascii wide nocase
        $guid_87135ab4_4cf7_454c_8830_38eb3ede1241_bin = { B4 5A 13 87 F7 4C 4C 45 88 30 38 EB 3E DE 12 41 }

        // steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // https://github.com/shaddy43/BrowserSnatch
        $guid_87440f0b_dacf_4695_a483_031fdc0b0194_str = "87440f0b-dacf-4695-a483-031fdc0b0194" ascii wide nocase
        $guid_87440f0b_dacf_4695_a483_031fdc0b0194_bin = { 0B 0F 44 87 CF DA 95 46 A4 83 03 1F DC 0B 01 94 }

        // Command and Control Framework written in C#
        // https://github.com/rasta-mouse/SharpC2
        $guid_87904247_C363_4F12_A13A_3DA484913F9E_str = "87904247-C363-4F12-A13A-3DA484913F9E" ascii wide nocase
        $guid_87904247_C363_4F12_A13A_3DA484913F9E_bin = { 47 42 90 87 63 C3 12 4F A1 3A 3D A4 84 91 3F 9E }

        // A tool for pointesters to find candies in SharePoint
        // https://github.com/nheiniger/SnaffPoint
        $guid_879A49C7_0493_4235_85F6_EBF962613A76_str = "879A49C7-0493-4235-85F6-EBF962613A76" ascii wide nocase
        $guid_879A49C7_0493_4235_85F6_EBF962613A76_bin = { C7 49 9A 87 93 04 35 42 85 F6 EB F9 62 61 3A 76 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_87BEF4D7_813E_48BA_96FE_E3A24BF2DC34_str = "87BEF4D7-813E-48BA-96FE-E3A24BF2DC34" ascii wide nocase
        $guid_87BEF4D7_813E_48BA_96FE_E3A24BF2DC34_bin = { D7 F4 BE 87 3E 81 BA 48 96 FE E3 A2 4B F2 DC 34 }

        // UAC Bypass By Abusing Kerberos Tickets
        // https://github.com/wh0amitz/KRBUACBypass
        $guid_881D4D67_46DD_4F40_A813_C9D3C8BE0965_str = "881D4D67-46DD-4F40-A813-C9D3C8BE0965" ascii wide nocase
        $guid_881D4D67_46DD_4F40_A813_C9D3C8BE0965_bin = { 67 4D 1D 88 DD 46 40 4F A8 13 C9 D3 C8 BE 09 65 }

        // UAC bypass for x64 Windows 7 - 11
        // https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $guid_8845A8AF_34DC_4EBC_8223_B35F8CC8A900_str = "8845A8AF-34DC-4EBC-8223-B35F8CC8A900" ascii wide nocase
        $guid_8845A8AF_34DC_4EBC_8223_B35F8CC8A900_bin = { AF A8 45 88 DC 34 BC 4E 82 23 B3 5F 8C C8 A9 00 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_886C26DC_0073_4BB7_823B_2B9DAD53DB8B_str = "886C26DC-0073-4BB7-823B-2B9DAD53DB8B" ascii wide nocase
        $guid_886C26DC_0073_4BB7_823B_2B9DAD53DB8B_bin = { DC 26 6C 88 73 00 B7 4B 82 3B 2B 9D AD 53 DB 8B }

        // .NET HttpClient proxy handler implementation for SOCKS proxies
        // https://github.com/bbepis/Nsocks
        $guid_889E3D8B_58FA_462D_A2D8_3CB430484B6A_str = "889E3D8B-58FA-462D-A2D8-3CB430484B6A" ascii wide nocase
        $guid_889E3D8B_58FA_462D_A2D8_3CB430484B6A_bin = { 8B 3D 9E 88 FA 58 2D 46 A2 D8 3C B4 30 48 4B 6A }

        // Shellcode Loader with memory evasion
        // https://github.com/RtlDallas/Jomungand
        $guid_88B40068_B3DB_4C2F_86F9_8EADC52CFE58_str = "88B40068-B3DB-4C2F-86F9-8EADC52CFE58" ascii wide nocase
        $guid_88B40068_B3DB_4C2F_86F9_8EADC52CFE58_bin = { 68 00 B4 88 DB B3 2F 4C 86 F9 8E AD C5 2C FE 58 }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_8923E1ED_2594_4668_A4FA_DC2CFF7EA1CA_str = "8923E1ED-2594-4668-A4FA-DC2CFF7EA1CA" ascii wide nocase
        $guid_8923E1ED_2594_4668_A4FA_DC2CFF7EA1CA_bin = { ED E1 23 89 94 25 68 46 A4 FA DC 2C FF 7E A1 CA }

        // Potato Privilege Escalation on Windows
        // https://github.com/foxglovesec/Potato
        $guid_893CC775_335D_4010_9751_D8C8E2A04048_str = "893CC775-335D-4010-9751-D8C8E2A04048" ascii wide nocase
        $guid_893CC775_335D_4010_9751_D8C8E2A04048_bin = { 75 C7 3C 89 5D 33 10 40 97 51 D8 C8 E2 A0 40 48 }

        // SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // https://github.com/BeichenDream/SharpToken
        $guid_894a784e_e04c_483c_a762_b6c03e744d0b_str = "894a784e-e04c-483c-a762-b6c03e744d0b" ascii wide nocase
        $guid_894a784e_e04c_483c_a762_b6c03e744d0b_bin = { 4E 78 4A 89 4C E0 3C 48 A7 62 B6 C0 3E 74 4D 0B }

        // SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // https://github.com/BeichenDream/SharpToken
        $guid_894A784E_E04C_483C_A762_B6C03E744D0B_str = "894A784E-E04C-483C-A762-B6C03E744D0B" ascii wide nocase
        $guid_894A784E_E04C_483C_A762_B6C03E744D0B_bin = { 4E 78 4A 89 4C E0 3C 48 A7 62 B6 C0 3E 74 4D 0B }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_8A15D28C_252A_4FCC_8BBD_BC3802C0320A_str = "8A15D28C-252A-4FCC-8BBD-BC3802C0320A" ascii wide nocase
        $guid_8A15D28C_252A_4FCC_8BBD_BC3802C0320A_bin = { 8C D2 15 8A 2A 25 CC 4F 8B BD BC 38 02 C0 32 0A }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_8A516D69_BA38_429F_AFFE_C571B5C1E482_str = "8A516D69-BA38-429F-AFFE-C571B5C1E482" ascii wide nocase
        $guid_8A516D69_BA38_429F_AFFE_C571B5C1E482_bin = { 69 6D 51 8A 38 BA 9F 42 AF FE C5 71 B5 C1 E4 82 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_8b1f0a69_a930_42e3_9c13_7de0d04a4add_str = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" ascii wide nocase
        $guid_8b1f0a69_a930_42e3_9c13_7de0d04a4add_bin = { 69 0A 1F 8B 30 A9 E3 42 9C 13 7D E0 D0 4A 4A DD }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_8B605B2E_AAD2_46FB_A348_27E3AABA4C9C_str = "8B605B2E-AAD2-46FB-A348-27E3AABA4C9C" ascii wide nocase
        $guid_8B605B2E_AAD2_46FB_A348_27E3AABA4C9C_bin = { 2E 5B 60 8B D2 AA FB 46 A3 48 27 E3 AA BA 4C 9C }

        // execute process as NT SERVICE\TrustedInstaller group account
        // https://github.com/daem0nc0re/PrivFu
        $guid_8B723CB2_017A_4CB6_B3E6_C26E9F1F8B3C_str = "8B723CB2-017A-4CB6-B3E6-C26E9F1F8B3C" ascii wide nocase
        $guid_8B723CB2_017A_4CB6_B3E6_C26E9F1F8B3C_bin = { B2 3C 72 8B 7A 01 B6 4C B3 E6 C2 6E 9F 1F 8B 3C }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_8B73C3EC_D0C4_4E0D_843A_67C81283EC5F_str = "8B73C3EC-D0C4-4E0D-843A-67C81283EC5F" ascii wide nocase
        $guid_8B73C3EC_D0C4_4E0D_843A_67C81283EC5F_bin = { EC C3 73 8B C4 D0 0D 4E 84 3A 67 C8 12 83 EC 5F }

        // AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // https://github.com/RythmStick/AMSITrigger
        $guid_8BAAEFF6_1840_4430_AA05_47F2877E3235_str = "8BAAEFF6-1840-4430-AA05-47F2877E3235" ascii wide nocase
        $guid_8BAAEFF6_1840_4430_AA05_47F2877E3235_bin = { F6 EF AA 8B 40 18 30 44 AA 05 47 F2 87 7E 32 35 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_8BF244EB_0CA3_403E_A076_F1D77731A728_str = "8BF244EB-0CA3-403E-A076-F1D77731A728" ascii wide nocase
        $guid_8BF244EB_0CA3_403E_A076_F1D77731A728_bin = { EB 44 F2 8B A3 0C 3E 40 A0 76 F1 D7 77 31 A7 28 }

        // a tool to help operate in EDRs' blind spots
        // https://github.com/naksyn/Pyramid
        $guid_8BF82BBE_909C_4777_A2FC_EA7C070FF43E_str = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" ascii wide nocase
        $guid_8BF82BBE_909C_4777_A2FC_EA7C070FF43E_bin = { BE 2B F8 8B 9C 90 77 47 A2 FC EA 7C 07 0F F4 3E }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_8BFC8ED2_71CC_49DC_9020_2C8199BC27B6_str = "8BFC8ED2-71CC-49DC-9020-2C8199BC27B6" ascii wide nocase
        $guid_8BFC8ED2_71CC_49DC_9020_2C8199BC27B6_bin = { D2 8E FC 8B CC 71 DC 49 90 20 2C 81 99 BC 27 B6 }

        // Injects a DLL into a suspended process running as SYSTEM via the OfficeClickToRun service for privilege escalation - Shim Injector: Injects a DLL into a process by modifying shim data in memory without creating or registering new SDB files to evade detection.
        // https://github.com/deepinstinct/ShimMe
        $guid_8cb4a31c_11c4_49e4_8c7a_b9c6df93f5d8_str = "8cb4a31c-11c4-49e4-8c7a-b9c6df93f5d8" ascii wide nocase
        $guid_8cb4a31c_11c4_49e4_8c7a_b9c6df93f5d8_bin = { 1C A3 B4 8C C4 11 E4 49 8C 7A B9 C6 DF 93 F5 D8 }

        // Remote Command Executor: A OSS replacement for PsExec and RunAs
        // https://github.com/kavika13/RemCom
        $guid_8CC59FFA_00E0_0AEA_59E8_E780672C3CB3_str = "8CC59FFA-00E0-0AEA-59E8-E780672C3CB3" ascii wide nocase
        $guid_8CC59FFA_00E0_0AEA_59E8_E780672C3CB3_bin = { FA 9F C5 8C E0 00 EA 0A 59 E8 E7 80 67 2C 3C B3 }

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_8D907846_455E_39A7_BD31_BC9F81468B47_str = "8D907846-455E-39A7-BD31-BC9F81468B47" ascii wide nocase
        $guid_8D907846_455E_39A7_BD31_BC9F81468B47_bin = { 46 78 90 8D 5E 45 A7 39 BD 31 BC 9F 81 46 8B 47 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_8dac9832_d464_4916_b102_9efa913bdc44_str = "8dac9832-d464-4916-b102-9efa913bdc44" ascii wide nocase
        $guid_8dac9832_d464_4916_b102_9efa913bdc44_bin = { 32 98 AC 8D 64 D4 16 49 B1 02 9E FA 91 3B DC 44 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_8DE42DA3_BE99_4E7E_A3D2_3F65E7C1ABCE_str = "8DE42DA3-BE99-4E7E-A3D2-3F65E7C1ABCE" ascii wide nocase
        $guid_8DE42DA3_BE99_4E7E_A3D2_3F65E7C1ABCE_bin = { A3 2D E4 8D 99 BE 7E 4E A3 D2 3F 65 E7 C1 AB CE }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_8DED0EC8_3611_4481_88FC_14B82531FD2B_str = "8DED0EC8-3611-4481-88FC-14B82531FD2B" ascii wide nocase
        $guid_8DED0EC8_3611_4481_88FC_14B82531FD2B_bin = { C8 0E ED 8D 11 36 81 44 88 FC 14 B8 25 31 FD 2B }

        // Recovering NTLM hashes from Credential Guard
        // https://github.com/ly4k/PassTheChallenge
        $guid_8F018213_4136_4D97_9084_F0346BBED04F_str = "8F018213-4136-4D97-9084-F0346BBED04F" ascii wide nocase
        $guid_8F018213_4136_4D97_9084_F0346BBED04F_bin = { 13 82 01 8F 36 41 97 4D 90 84 F0 34 6B BE D0 4F }

        // enable or disable specific token privileges for a process
        // https://github.com/daem0nc0re/PrivFu
        $guid_8F208DB9_7555_46D5_A5FE_2D7E85E05CAA_str = "8F208DB9-7555-46D5-A5FE-2D7E85E05CAA" ascii wide nocase
        $guid_8F208DB9_7555_46D5_A5FE_2D7E85E05CAA_bin = { B9 8D 20 8F 55 75 D5 46 A5 FE 2D 7E 85 E0 5C AA }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_8F71C671_F53C_4F4F_98B9_8B8D3263C0DB_str = "8F71C671-F53C-4F4F-98B9-8B8D3263C0DB" ascii wide nocase
        $guid_8F71C671_F53C_4F4F_98B9_8B8D3263C0DB_bin = { 71 C6 71 8F 3C F5 4F 4F 98 B9 8B 8D 32 63 C0 DB }

        // Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // https://github.com/CCob/DRSAT
        $guid_8FC203AA_8A90_4A15_B823_E2C3BC4DF0D6_str = "8FC203AA-8A90-4A15-B823-E2C3BC4DF0D6" ascii wide nocase
        $guid_8FC203AA_8A90_4A15_B823_E2C3BC4DF0D6_bin = { AA 03 C2 8F 90 8A 15 4A B8 23 E2 C3 BC 4D F0 D6 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_901E099B_A01A_4F21_9A6F_8D3B60F04168_str = "901E099B-A01A-4F21-9A6F-8D3B60F04168" ascii wide nocase
        $guid_901E099B_A01A_4F21_9A6F_8D3B60F04168_bin = { 9B 09 1E 90 1A A0 21 4F 9A 6F 8D 3B 60 F0 41 68 }

        // MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // https://github.com/Xre0uS/MultiDump
        $guid_90229D7D_5CC2_4C1E_80D3_4B7C7289B480_str = "90229D7D-5CC2-4C1E-80D3-4B7C7289B480" ascii wide nocase
        $guid_90229D7D_5CC2_4C1E_80D3_4B7C7289B480_bin = { 7D 9D 22 90 C2 5C 1E 4C 80 D3 4B 7C 72 89 B4 80 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_9042B543_13D1_42B3_A5B6_5CC9AD55E150_str = "9042B543-13D1-42B3-A5B6-5CC9AD55E150" ascii wide nocase
        $guid_9042B543_13D1_42B3_A5B6_5CC9AD55E150_bin = { 43 B5 42 90 D1 13 B3 42 A5 B6 5C C9 AD 55 E1 50 }

        // C# Data Collector for BloodHound
        // https://github.com/BloodHoundAD/SharpHound
        $guid_90A6822C_4336_433D_923F_F54CE66BA98F_str = "90A6822C-4336-433D-923F-F54CE66BA98F" ascii wide nocase
        $guid_90A6822C_4336_433D_923F_F54CE66BA98F_bin = { 2C 82 A6 90 36 43 3D 43 92 3F F5 4C E6 6B A9 8F }

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_90DEB964_F2FB_4DB8_9BCA_7D5D10D3A0EB_str = "90DEB964-F2FB-4DB8-9BCA-7D5D10D3A0EB" ascii wide nocase
        $guid_90DEB964_F2FB_4DB8_9BCA_7D5D10D3A0EB_bin = { 64 B9 DE 90 FB F2 B8 4D 9B CA 7D 5D 10 D3 A0 EB }

        // tool written in C# that aims to do enumeration via LDAP queries
        // https://github.com/mertdas/SharpLDAP
        $guid_90F6244A_5EEE_4A7A_8C75_FA6A52DF34D3_str = "90F6244A-5EEE-4A7A-8C75-FA6A52DF34D3" ascii wide nocase
        $guid_90F6244A_5EEE_4A7A_8C75_FA6A52DF34D3_bin = { 4A 24 F6 90 EE 5E 7A 4A 8C 75 FA 6A 52 DF 34 D3 }

        // SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // https://github.com/StarfireLab/SharpWeb
        $guid_91292bac_72b4_4aab_9e5f_2bc1843c8ea3_str = "91292bac-72b4-4aab-9e5f-2bc1843c8ea3" ascii wide nocase
        $guid_91292bac_72b4_4aab_9e5f_2bc1843c8ea3_bin = { AC 2B 29 91 B4 72 AB 4A 9E 5F 2B C1 84 3C 8E A3 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_91B12706_DC6A_45DE_97F1_FAF0901FF6AF_str = "91B12706-DC6A-45DE-97F1-FAF0901FF6AF" ascii wide nocase
        $guid_91B12706_DC6A_45DE_97F1_FAF0901FF6AF_bin = { 06 27 B1 91 6A DC DE 45 97 F1 FA F0 90 1F F6 AF }

        // Command and Control Framework written in C#
        // https://github.com/rasta-mouse/SharpC2
        $guid_91EA50CD_E8DF_4EDF_A765_75354643BD0D_str = "91EA50CD-E8DF-4EDF-A765-75354643BD0D" ascii wide nocase
        $guid_91EA50CD_E8DF_4EDF_A765_75354643BD0D_bin = { CD 50 EA 91 DF E8 DF 4E A7 65 75 35 46 43 BD 0D }

        // Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // https://github.com/b4rtik/ATPMiniDump
        $guid_920B8C5B_0DC5_4BD7_B6BB_D14B39BFC9FE_str = "920B8C5B-0DC5-4BD7-B6BB-D14B39BFC9FE" ascii wide nocase
        $guid_920B8C5B_0DC5_4BD7_B6BB_D14B39BFC9FE_bin = { 5B 8C 0B 92 C5 0D D7 4B B6 BB D1 4B 39 BF C9 FE }

        // A C# Command & Control framework
        // https://github.com/DragoQCC/HardHatC2
        $guid_920D97B7_8091_4224_8CF7_D9D72A64A7FE_str = "920D97B7-8091-4224-8CF7-D9D72A64A7FE" ascii wide nocase
        $guid_920D97B7_8091_4224_8CF7_D9D72A64A7FE_bin = { B7 97 0D 92 91 80 24 42 8C F7 D9 D7 2A 64 A7 FE }

        // mimikatz UUID
        // https://github.com/gentilkiwi/mimikatz
        $guid_921BB3E1_15EE_4bbe_83D4_C4CE176A481B_str = "921BB3E1-15EE-4bbe-83D4-C4CE176A481B" ascii wide nocase
        $guid_921BB3E1_15EE_4bbe_83D4_C4CE176A481B_bin = { E1 B3 1B 92 EE 15 BE 4B 83 D4 C4 CE 17 6A 48 1B }

        // WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // https://github.com/pwn1sher/WMEye
        $guid_928120DC_5275_4806_B99B_12D67B710DC0_str = "928120DC-5275-4806-B99B-12D67B710DC0" ascii wide nocase
        $guid_928120DC_5275_4806_B99B_12D67B710DC0_bin = { DC 20 81 92 75 52 06 48 B9 9B 12 D6 7B 71 0D C0 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_92C5208E_DE76_49F9_B022_1A558C95B6DF_str = "92C5208E-DE76-49F9-B022-1A558C95B6DF" ascii wide nocase
        $guid_92C5208E_DE76_49F9_B022_1A558C95B6DF_bin = { 8E 20 C5 92 76 DE F9 49 B0 22 1A 55 8C 95 B6 DF }

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_9341205B_AEE0_483B_9A80_975C2084C3AE_str = "9341205B-AEE0-483B-9A80-975C2084C3AE" ascii wide nocase
        $guid_9341205B_AEE0_483B_9A80_975C2084C3AE_bin = { 5B 20 41 93 E0 AE 3B 48 9A 80 97 5C 20 84 C3 AE }

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_935D33C5_62F1_40FE_8DB0_46B6E01342FB_str = "935D33C5-62F1-40FE-8DB0-46B6E01342FB" ascii wide nocase
        $guid_935D33C5_62F1_40FE_8DB0_46B6E01342FB_bin = { C5 33 5D 93 F1 62 FE 40 8D B0 46 B6 E0 13 42 FB }

        // Cronos is Windows 10/11 x64 ring 0 rootkit. Cronos is able to hide processes. protect and elevate them with token manipulation.
        // https://github.com/XaFF-XaFF/Cronos-Rootkit
        $guid_940B1177_2B8C_48A2_A8E7_BF4E8E80C60F_str = "940B1177-2B8C-48A2-A8E7-BF4E8E80C60F" ascii wide nocase
        $guid_940B1177_2B8C_48A2_A8E7_BF4E8E80C60F_bin = { 77 11 0B 94 8C 2B A2 48 A8 E7 BF 4E 8E 80 C6 0F }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_9434E131_51CD_4FC6_9105_D73734DC5BA6_str = "9434E131-51CD-4FC6-9105-D73734DC5BA6" ascii wide nocase
        $guid_9434E131_51CD_4FC6_9105_D73734DC5BA6_bin = { 31 E1 34 94 CD 51 C6 4F 91 05 D7 37 34 DC 5B A6 }

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_946619C2_5959_4C0C_BC7C_1C27D825B042_str = "946619C2-5959-4C0C-BC7C-1C27D825B042" ascii wide nocase
        $guid_946619C2_5959_4C0C_BC7C_1C27D825B042_bin = { C2 19 66 94 59 59 0C 4C BC 7C 1C 27 D8 25 B0 42 }

        // Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // https://github.com/reveng007/SharpGmailC2
        $guid_946D24E4_201B_4D51_AF9A_3190266E0E1B_str = "946D24E4-201B-4D51-AF9A-3190266E0E1B" ascii wide nocase
        $guid_946D24E4_201B_4D51_AF9A_3190266E0E1B_bin = { E4 24 6D 94 1B 20 51 4D AF 9A 31 90 26 6E 0E 1B }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_94AEDCE4_D4A2_45DB_B98E_860EE6BE8385_str = "94AEDCE4-D4A2-45DB-B98E-860EE6BE8385" ascii wide nocase
        $guid_94AEDCE4_D4A2_45DB_B98E_860EE6BE8385_bin = { E4 DC AE 94 A2 D4 DB 45 B9 8E 86 0E E6 BE 83 85 }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_94DE5045_4D09_437B_BDE3_679FCAF07A2D_str = "94DE5045-4D09-437B-BDE3-679FCAF07A2D" ascii wide nocase
        $guid_94DE5045_4D09_437B_BDE3_679FCAF07A2D_bin = { 45 50 DE 94 09 4D 7B 43 BD E3 67 9F CA F0 7A 2D }

        // alternative to the Cobalt Strike Beacon
        // https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon
        $guid_95502b5e_5763_4ec5_a64c_1e9e33409e2f_str = "95502b5e-5763-4ec5-a64c-1e9e33409e2f" ascii wide nocase
        $guid_95502b5e_5763_4ec5_a64c_1e9e33409e2f_bin = { 5E 2B 50 95 63 57 C5 4E A6 4C 1E 9E 33 40 9E 2F }

        // Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // https://github.com/zer0condition/ZeroHVCI
        $guid_95529189_2fb6_49e4_ab2d_3c925ada4414_str = "95529189-2fb6-49e4-ab2d-3c925ada4414" ascii wide nocase
        $guid_95529189_2fb6_49e4_ab2d_3c925ada4414_bin = { 89 91 52 95 B6 2F E4 49 AB 2D 3C 92 5A DA 44 14 }

        // C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // https://github.com/Hagrid29/DumpAADSyncCreds
        $guid_95A40D7C_F3F7_4C45_8C5A_D384DE50B6C9_str = "95A40D7C-F3F7-4C45-8C5A-D384DE50B6C9" ascii wide nocase
        $guid_95A40D7C_F3F7_4C45_8C5A_D384DE50B6C9_bin = { 7C 0D A4 95 F7 F3 45 4C 8C 5A D3 84 DE 50 B6 C9 }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_95BB9D5E_260F_4A70_B0FA_0757A94EF677_str = "95BB9D5E-260F-4A70-B0FA-0757A94EF677" ascii wide nocase
        $guid_95BB9D5E_260F_4A70_B0FA_0757A94EF677_bin = { 5E 9D BB 95 0F 26 70 4A B0 FA 07 57 A9 4E F6 77 }

        // Adaptive DLL hijacking / dynamic export forwarding
        // https://github.com/monoxgas/Koppeling
        $guid_95BC2C38_1FBE_4AF1_967E_BC133250C4D4_str = "95BC2C38-1FBE-4AF1-967E-BC133250C4D4" ascii wide nocase
        $guid_95BC2C38_1FBE_4AF1_967E_BC133250C4D4_bin = { 38 2C BC 95 BE 1F F1 4A 96 7E BC 13 32 50 C4 D4 }

        // Leverage a legitimate WFP callout driver to prevent EDR agents from sending telemetry
        // https://github.com/senzee1984/EDRPrison
        $guid_9674DF71_0814_4398_8A77_5A32A8CBE61E_str = "9674DF71-0814-4398-8A77-5A32A8CBE61E" ascii wide nocase
        $guid_9674DF71_0814_4398_8A77_5A32A8CBE61E_bin = { 71 DF 74 96 14 08 98 43 8A 77 5A 32 A8 CB E6 1E }

        // monitor the content of the clipboard continuously
        // http://github.com/slyd0g/SharpClipboard
        $guid_97484211_4726_4129_86AA_AE01D17690BE_str = "97484211-4726-4129-86AA-AE01D17690BE" ascii wide nocase
        $guid_97484211_4726_4129_86AA_AE01D17690BE_bin = { 11 42 48 97 26 47 29 41 86 AA AE 01 D1 76 90 BE }

        // This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // https://github.com/passthehashbrowns/SharpBuster
        $guid_9786E418_6C4A_471D_97C0_8B5F2ED524C8_str = "9786E418-6C4A-471D-97C0-8B5F2ED524C8" ascii wide nocase
        $guid_9786E418_6C4A_471D_97C0_8B5F2ED524C8_bin = { 18 E4 86 97 4A 6C 1D 47 97 C0 8B 5F 2E D5 24 C8 }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_97C056B0_2AEB_4467_AAC9_E0FE0639BA9E_str = "97C056B0-2AEB-4467-AAC9-E0FE0639BA9E" ascii wide nocase
        $guid_97C056B0_2AEB_4467_AAC9_E0FE0639BA9E_bin = { B0 56 C0 97 EB 2A 67 44 AA C9 E0 FE 06 39 BA 9E }

        // A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // https://github.com/bats3c/ADCSPwn
        $guid_980EF05F_87D1_4A0A_932A_582FB1BC3AC3_str = "980EF05F-87D1-4A0A-932A-582FB1BC3AC3" ascii wide nocase
        $guid_980EF05F_87D1_4A0A_932A_582FB1BC3AC3_bin = { 5F F0 0E 98 D1 87 0A 4A 93 2A 58 2F B1 BC 3A C3 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_989A9793_63FC_4639_8A8D_E4BB9F60F137_str = "989A9793-63FC-4639-8A8D-E4BB9F60F137" ascii wide nocase
        $guid_989A9793_63FC_4639_8A8D_E4BB9F60F137_bin = { 93 97 9A 98 FC 63 39 46 8A 8D E4 BB 9F 60 F1 37 }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_99142A50_E046_4F18_9C52_9855ABADA9B3_str = "99142A50-E046-4F18-9C52-9855ABADA9B3" ascii wide nocase
        $guid_99142A50_E046_4F18_9C52_9855ABADA9B3_bin = { 50 2A 14 99 46 E0 18 4F 9C 52 98 55 AB AD A9 B3 }

        // SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // https://github.com/StarfireLab/SharpWeb
        $guid_99292BAC_72B4_4AAB_9E5F_2BC1843C8EA3_str = "99292BAC-72B4-4AAB-9E5F-2BC1843C8EA3" ascii wide nocase
        $guid_99292BAC_72B4_4AAB_9E5F_2BC1843C8EA3_bin = { AC 2B 29 99 B4 72 AB 4A 9E 5F 2B C1 84 3C 8E A3 }

        // C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // https://github.com/Adaptix-Framework/AdaptixC2
        $guid_99a5f42e_60a8_4f1e_9dff_35443b972707_str = "99a5f42e-60a8-4f1e-9dff-35443b972707" ascii wide nocase
        $guid_99a5f42e_60a8_4f1e_9dff_35443b972707_bin = { 2E F4 A5 99 A8 60 1E 4F 9D FF 35 44 3B 97 27 07 }

        // Windows Antivirus Comparison and Patch Number Comparison
        // https://github.com/uknowsec/SharpAVKB
        $guid_99DDC600_3E6F_435E_89DF_74439FA68061_str = "99DDC600-3E6F-435E-89DF-74439FA68061" ascii wide nocase
        $guid_99DDC600_3E6F_435E_89DF_74439FA68061_bin = { 00 C6 DD 99 6F 3E 5E 43 89 DF 74 43 9F A6 80 61 }

        // The OpenBullet web testing application.
        // https://github.com/openbullet/openbullet
        $guid_99E40E7F_00A4_4FB1_9441_B05A56C47C08_str = "99E40E7F-00A4-4FB1-9441-B05A56C47C08" ascii wide nocase
        $guid_99E40E7F_00A4_4FB1_9441_B05A56C47C08_bin = { 7F 0E E4 99 A4 00 B1 4F 94 41 B0 5A 56 C4 7C 08 }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_9A374E66_70B5_433D_8D7D_89E3F8AC0617_str = "9A374E66-70B5-433D-8D7D-89E3F8AC0617" ascii wide nocase
        $guid_9A374E66_70B5_433D_8D7D_89E3F8AC0617_bin = { 66 4E 37 9A B5 70 3D 43 8D 7D 89 E3 F8 AC 06 17 }

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_9AA32BBF_90F3_4CE6_B210_CBCDB85052B0_str = "9AA32BBF-90F3-4CE6-B210-CBCDB85052B0" ascii wide nocase
        $guid_9AA32BBF_90F3_4CE6_B210_CBCDB85052B0_bin = { BF 2B A3 9A F3 90 E6 4C B2 10 CB CD B8 50 52 B0 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_9B823D93_BF1B_407B_A4CD_231347F656AD_str = "9B823D93-BF1B-407B-A4CD-231347F656AD" ascii wide nocase
        $guid_9B823D93_BF1B_407B_A4CD_231347F656AD_bin = { 93 3D 82 9B 1B BF 7B 40 A4 CD 23 13 47 F6 56 AD }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_9C30CAE4_6FBE_45CC_90C2_1D739DB92E86_str = "9C30CAE4-6FBE-45CC-90C2-1D739DB92E86" ascii wide nocase
        $guid_9C30CAE4_6FBE_45CC_90C2_1D739DB92E86_bin = { E4 CA 30 9C BE 6F CC 45 90 C2 1D 73 9D B9 2E 86 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_9CCE5C71_14B4_4A08_958D_4E593975658B_str = "9CCE5C71-14B4-4A08-958D-4E593975658B" ascii wide nocase
        $guid_9CCE5C71_14B4_4A08_958D_4E593975658B_bin = { 71 5C CE 9C B4 14 08 4A 95 8D 4E 59 39 75 65 8B }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_9CFD5FA4_5AD6_463C_87E5_3F42133B5DA8_str = "9CFD5FA4-5AD6-463C-87E5-3F42133B5DA8" ascii wide nocase
        $guid_9CFD5FA4_5AD6_463C_87E5_3F42133B5DA8_bin = { A4 5F FD 9C D6 5A 3C 46 87 E5 3F 42 13 3B 5D A8 }

        // SharPersist Windows persistence toolkit written in C#.
        // https://github.com/fireeye/SharPersist
        $guid_9D1B853E_58F1_4BA5_AEFC_5C221CA30E48_str = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii wide nocase
        $guid_9D1B853E_58F1_4BA5_AEFC_5C221CA30E48_bin = { 3E 85 1B 9D F1 58 A5 4B AE FC 5C 22 1C A3 0E 48 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_9D1D39D8_2387_46ED_A4A8_59D250C97F35_str = "9D1D39D8-2387-46ED-A4A8-59D250C97F35" ascii wide nocase
        $guid_9D1D39D8_2387_46ED_A4A8_59D250C97F35_bin = { D8 39 1D 9D 87 23 ED 46 A4 A8 59 D2 50 C9 7F 35 }

        // Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // https://github.com/TheD1rkMtr/NTDLLReflection
        $guid_9D365106_D7B8_4B5E_82CC_6D6ABCDCA2B8_str = "9D365106-D7B8-4B5E-82CC-6D6ABCDCA2B8" ascii wide nocase
        $guid_9D365106_D7B8_4B5E_82CC_6D6ABCDCA2B8_bin = { 06 51 36 9D B8 D7 5E 4B 82 CC 6D 6A BC DC A2 B8 }

        // Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // https://github.com/OG-Sadpanda/SharpSword
        $guid_9E357027_8AA6_4376_8146_F5AF610E14BB_str = "9E357027-8AA6-4376-8146-F5AF610E14BB" ascii wide nocase
        $guid_9E357027_8AA6_4376_8146_F5AF610E14BB_bin = { 27 70 35 9E A6 8A 76 43 81 46 F5 AF 61 0E 14 BB }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_9E36AE6E_B9FD_4B9B_99BA_42D3EACD7506_str = "9E36AE6E-B9FD-4B9B-99BA-42D3EACD7506" ascii wide nocase
        $guid_9E36AE6E_B9FD_4B9B_99BA_42D3EACD7506_bin = { 6E AE 36 9E FD B9 9B 4B 99 BA 42 D3 EA CD 75 06 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_9E5A6F99_0A26_4959_847D_A4221CF4441B_str = "9E5A6F99-0A26-4959-847D-A4221CF4441B" ascii wide nocase
        $guid_9E5A6F99_0A26_4959_847D_A4221CF4441B_bin = { 99 6F 5A 9E 26 0A 59 49 84 7D A4 22 1C F4 44 1B }

        // Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // https://github.com/ricardojoserf/TrickDump
        $guid_9E9BB94C_1FBE_4D0B_83B7_E42C83FC5D45_str = "9E9BB94C-1FBE-4D0B-83B7-E42C83FC5D45" ascii wide nocase
        $guid_9E9BB94C_1FBE_4D0B_83B7_E42C83FC5D45_bin = { 4C B9 9B 9E BE 1F 0B 4D 83 B7 E4 2C 83 FC 5D 45 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_9EB8DC3B_60DC_451E_8C18_3D7E38D463FD_str = "9EB8DC3B-60DC-451E-8C18-3D7E38D463FD" ascii wide nocase
        $guid_9EB8DC3B_60DC_451E_8C18_3D7E38D463FD_bin = { 3B DC B8 9E DC 60 1E 45 8C 18 3D 7E 38 D4 63 FD }

        // A C# tool to dump all sorts of goodies from AD FS
        // https://github.com/mandiant/ADFSDump
        $guid_9EE27D63_6AC9_4037_860B_44E91BAE7F0D_str = "9EE27D63-6AC9-4037-860B-44E91BAE7F0D" ascii wide nocase
        $guid_9EE27D63_6AC9_4037_860B_44E91BAE7F0D_bin = { 63 7D E2 9E C9 6A 37 40 86 0B 44 E9 1B AE 7F 0D }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_9EFFFF7A_DC03_4D52_BB8F_F0140FAD26E7_str = "9EFFFF7A-DC03-4D52-BB8F-F0140FAD26E7" ascii wide nocase
        $guid_9EFFFF7A_DC03_4D52_BB8F_F0140FAD26E7_bin = { 7A FF FF 9E 03 DC 52 4D BB 8F F0 14 0F AD 26 E7 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_9F5CF56A_DDB2_4F40_AB99_2A1DC47588E1_str = "9F5CF56A-DDB2-4F40-AB99-2A1DC47588E1" ascii wide nocase
        $guid_9F5CF56A_DDB2_4F40_AB99_2A1DC47588E1_bin = { 6A F5 5C 9F B2 DD 40 4F AB 99 2A 1D C4 75 88 E1 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_9FEA6712_3880_4E5F_BD56_8E58A4EBCCB4_str = "9FEA6712-3880-4E5F-BD56-8E58A4EBCCB4" ascii wide nocase
        $guid_9FEA6712_3880_4E5F_BD56_8E58A4EBCCB4_bin = { 12 67 EA 9F 80 38 5F 4E BD 56 8E 58 A4 EB CC B4 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_A017568E_B62E_46B4_9557_15B278656365_str = "A017568E-B62E-46B4-9557-15B278656365" ascii wide nocase
        $guid_A017568E_B62E_46B4_9557_15B278656365_bin = { 8E 56 17 A0 2E B6 B4 46 95 57 15 B2 78 65 63 65 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_A0E096FB_3AEF_41B5_A67B_BD90D2FEBBFC_str = "A0E096FB-3AEF-41B5-A67B-BD90D2FEBBFC" ascii wide nocase
        $guid_A0E096FB_3AEF_41B5_A67B_BD90D2FEBBFC_bin = { FB 96 E0 A0 EF 3A B5 41 A6 7B BD 90 D2 FE BB FC }

        // A tool to kill antimalware protected processes
        // https://github.com/Yaxser/Backstab
        $guid_A0E7B538_F719_47B8_8BE4_A82C933F5753_str = "A0E7B538-F719-47B8-8BE4-A82C933F5753" ascii wide nocase
        $guid_A0E7B538_F719_47B8_8BE4_A82C933F5753_bin = { 38 B5 E7 A0 19 F7 B8 47 8B E4 A8 2C 93 3F 57 53 }

        // TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // https://github.com/Flangvik/TeamFiltration
        $guid_A0F044C5_D910_4720_B082_58824E372281_str = "A0F044C5-D910-4720-B082-58824E372281" ascii wide nocase
        $guid_A0F044C5_D910_4720_B082_58824E372281_bin = { C5 44 F0 A0 10 D9 20 47 B0 82 58 82 4E 37 22 81 }

        // leverages the NetUserAdd Win32 API to create a new computer account
        // https://github.com/Ben0xA/DoUCMe
        $guid_A11E7DAE_21F2_46A8_991E_D38DEBE1650F_str = "A11E7DAE-21F2-46A8-991E-D38DEBE1650F" ascii wide nocase
        $guid_A11E7DAE_21F2_46A8_991E_D38DEBE1650F_bin = { AE 7D 1E A1 F2 21 A8 46 99 1E D3 8D EB E1 65 0F }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_A138FC2A_7BFF_4B3C_94A0_62A8BC01E8C0_str = "A138FC2A-7BFF-4B3C-94A0-62A8BC01E8C0" ascii wide nocase
        $guid_A138FC2A_7BFF_4B3C_94A0_62A8BC01E8C0_bin = { 2A FC 38 A1 FF 7B 3C 4B 94 A0 62 A8 BC 01 E8 C0 }

        // Run Powershell without software restrictions.
        // https://github.com/iomoath/PowerShx
        $guid_A17656B2_42D1_42CD_B76D_9B60F637BCB5_str = "A17656B2-42D1-42CD-B76D-9B60F637BCB5" ascii wide nocase
        $guid_A17656B2_42D1_42CD_B76D_9B60F637BCB5_bin = { B2 56 76 A1 D1 42 CD 42 B7 6D 9B 60 F6 37 BC B5 }

        // Shim database persistence (Fin7 TTP)
        // https://github.com/jackson5sec/ShimDB
        $guid_A1A949A4_5CE4_4FCF_A3B9_A2290EA46086_str = "A1A949A4-5CE4-4FCF-A3B9-A2290EA46086" ascii wide nocase
        $guid_A1A949A4_5CE4_4FCF_A3B9_A2290EA46086_bin = { A4 49 A9 A1 E4 5C CF 4F A3 B9 A2 29 0E A4 60 86 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_A1F54816_3FBA_4A71_9D26_D31C6BE9CF01_str = "A1F54816-3FBA-4A71-9D26-D31C6BE9CF01" ascii wide nocase
        $guid_A1F54816_3FBA_4A71_9D26_D31C6BE9CF01_bin = { 16 48 F5 A1 BA 3F 71 4A 9D 26 D3 1C 6B E9 CF 01 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_A2107C86_7CB5_45EE_89E8_1BC7261F7762_str = "A2107C86-7CB5-45EE-89E8-1BC7261F7762" ascii wide nocase
        $guid_A2107C86_7CB5_45EE_89E8_1BC7261F7762_bin = { 86 7C 10 A2 B5 7C EE 45 89 E8 1B C7 26 1F 77 62 }

        // Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $guid_A220F564_41CB_46F5_9938_FEFD87819771_str = "A220F564-41CB-46F5-9938-FEFD87819771" ascii wide nocase
        $guid_A220F564_41CB_46F5_9938_FEFD87819771_bin = { 64 F5 20 A2 CB 41 F5 46 99 38 FE FD 87 81 97 71 }

        // Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // https://github.com/wh0amitz/PetitPotato
        $guid_A315E53B_397A_4074_B988_535A100D45DC_str = "A315E53B-397A-4074-B988-535A100D45DC" ascii wide nocase
        $guid_A315E53B_397A_4074_B988_535A100D45DC_bin = { 3B E5 15 A3 7A 39 74 40 B9 88 53 5A 10 0D 45 DC }

        // inspect token information
        // https://github.com/daem0nc0re/PrivFu
        $guid_A318BEE3_2BDB_41A1_BE56_956774BBC12B_str = "A318BEE3-2BDB-41A1-BE56-956774BBC12B" ascii wide nocase
        $guid_A318BEE3_2BDB_41A1_BE56_956774BBC12B_bin = { E3 BE 18 A3 DB 2B A1 41 BE 56 95 67 74 BB C1 2B }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_a336f517_bca9_465f_8ff8_2756cfd0cad9_str = "a336f517-bca9-465f-8ff8-2756cfd0cad9" ascii wide nocase
        $guid_a336f517_bca9_465f_8ff8_2756cfd0cad9_bin = { 17 F5 36 A3 A9 BC 5F 46 8F F8 27 56 CF D0 CA D9 }

        // enabling Recall in Windows 11 version 24H2 on unsupported devices
        // https://github.com/thebookisclosed/AmperageKit
        $guid_A3454AF1_12AF_4952_B26D_FF0930DB779E_str = "A3454AF1-12AF-4952-B26D-FF0930DB779E" ascii wide nocase
        $guid_A3454AF1_12AF_4952_B26D_FF0930DB779E_bin = { F1 4A 45 A3 AF 12 52 49 B2 6D FF 09 30 DB 77 9E }

        // DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // https://github.com/DavidXanatos/DiskCryptor
        $guid_A38C04C7_B172_4897_8471_E3478903035E_str = "A38C04C7-B172-4897-8471-E3478903035E" ascii wide nocase
        $guid_A38C04C7_B172_4897_8471_E3478903035E_bin = { C7 04 8C A3 72 B1 97 48 84 71 E3 47 89 03 03 5E }

        // a NetBIOS scanner. Ghost actors use this tool for hostname and IP address enumeration
        // https://github.com/BronzeTicket/SharpNBTScan
        $guid_a398655a_d83f_46bf_8173_3ad16260d970_str = "a398655a-d83f-46bf-8173-3ad16260d970" ascii wide nocase
        $guid_a398655a_d83f_46bf_8173_3ad16260d970_bin = { 5A 65 98 A3 3F D8 BF 46 81 73 3A D1 62 60 D9 70 }

        // Metasploit is a widely-used. open-source framework designed for penetration testing. vulnerability assessment. and exploit development. It provides security professionals and researchers with a comprehensive platform to discover. exploit. and validate vulnerabilities in computer systems and networks. Metasploit includes a large database of pre-built exploits. payloads. and auxiliary modules that can be used to test various attack vectors. identify security weaknesses. and simulate real-world cyberattacks. By utilizing Metasploit. security teams can better understand potential threats and improve their overall security posture.
        // https://github.com/rapid7/metasploit-omnibus
        $guid_A3C83F57_6D8F_453A_9559_0D650A95EB21_str = "A3C83F57-6D8F-453A-9559-0D650A95EB21" ascii wide nocase
        $guid_A3C83F57_6D8F_453A_9559_0D650A95EB21_bin = { 57 3F C8 A3 8F 6D 3A 45 95 59 0D 65 0A 95 EB 21 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_A45C184F_F98F_4258_A928_BFF437034791_str = "A45C184F-F98F-4258-A928-BFF437034791" ascii wide nocase
        $guid_A45C184F_F98F_4258_A928_BFF437034791_bin = { 4F 18 5C A4 8F F9 58 42 A9 28 BF F4 37 03 47 91 }

        // Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // https://github.com/exploits-forsale/prefetch-tool
        $guid_A46C9A13_145E_42C0_8CA6_CC920BF1D9F1_str = "A46C9A13-145E-42C0-8CA6-CC920BF1D9F1" ascii wide nocase
        $guid_A46C9A13_145E_42C0_8CA6_CC920BF1D9F1_bin = { 13 9A 6C A4 5E 14 C0 42 8C A6 CC 92 0B F1 D9 F1 }

        // C# Data Collector for BloodHound
        // https://github.com/BloodHoundAD/SharpHound
        $guid_A517A8DE_5834_411D_ABDA_2D0E1766539C_str = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii wide nocase
        $guid_A517A8DE_5834_411D_ABDA_2D0E1766539C_bin = { DE A8 17 A5 34 58 1D 41 AB DA 2D 0E 17 66 53 9C }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_A5B912EC_D588_401C_A84F_D01F98142B9E_str = "A5B912EC-D588-401C-A84F-D01F98142B9E" ascii wide nocase
        $guid_A5B912EC_D588_401C_A84F_D01F98142B9E_bin = { EC 12 B9 A5 88 D5 1C 40 A8 4F D0 1F 98 14 2B 9E }

        // AV/EDR evasion
        // https://github.com/myzxcg/RealBlindingEDR
        $guid_A62776D0_CF96_4067_B4BE_B337AB6DFF02_str = "A62776D0-CF96-4067-B4BE-B337AB6DFF02" ascii wide nocase
        $guid_A62776D0_CF96_4067_B4BE_B337AB6DFF02_bin = { D0 76 27 A6 96 CF 67 40 B4 BE B3 37 AB 6D FF 02 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_A6497C83_7DC7_4E48_87BA_FB5DFAABE3C9_str = "A6497C83-7DC7-4E48-87BA-FB5DFAABE3C9" ascii wide nocase
        $guid_A6497C83_7DC7_4E48_87BA_FB5DFAABE3C9_bin = { 83 7C 49 A6 C7 7D 48 4E 87 BA FB 5D FA AB E3 C9 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_A64EF001_BE90_4CF5_86B2_22DFDB49AE81_str = "A64EF001-BE90-4CF5-86B2-22DFDB49AE81" ascii wide nocase
        $guid_A64EF001_BE90_4CF5_86B2_22DFDB49AE81_bin = { 01 F0 4E A6 90 BE F5 4C 86 B2 22 DF DB 49 AE 81 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_A663D4C5_BC01_42A6_9C65_52F0524B4AB7_str = "A663D4C5-BC01-42A6-9C65-52F0524B4AB7" ascii wide nocase
        $guid_A663D4C5_BC01_42A6_9C65_52F0524B4AB7_bin = { C5 D4 63 A6 01 BC A6 42 9C 65 52 F0 52 4B 4A B7 }

        // get current user credentials by popping a fake Windows lock screen
        // https://github.com/Pickfordmatt/SharpLocker
        $guid_A6F8500F_68BC_4EFC_962A_6C6E68D893AF_str = "A6F8500F-68BC-4EFC-962A-6C6E68D893AF" ascii wide nocase
        $guid_A6F8500F_68BC_4EFC_962A_6C6E68D893AF_bin = { 0F 50 F8 A6 BC 68 FC 4E 96 2A 6C 6E 68 D8 93 AF }

        // Tool for viewing NTDS.dit
        // https://github.com/trustedsec/DitExplorer
        $guid_A71FCCEB_C1C5_4ADB_A949_462B653C2937_str = "A71FCCEB-C1C5-4ADB-A949-462B653C2937" ascii wide nocase
        $guid_A71FCCEB_C1C5_4ADB_A949_462B653C2937_bin = { EB CC 1F A7 C5 C1 DB 4A A9 49 46 2B 65 3C 29 37 }

        // Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // https://github.com/itm4n/Perfusion
        $guid_A7397316_0AEF_4379_B285_C276DE02BDE1_str = "A7397316-0AEF-4379-B285-C276DE02BDE1" ascii wide nocase
        $guid_A7397316_0AEF_4379_B285_C276DE02BDE1_bin = { 16 73 39 A7 EF 0A 79 43 B2 85 C2 76 DE 02 BD E1 }

        // gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $guid_A7AD39B5_9BA1_48A9_B928_CA25FDD8F31F_str = "A7AD39B5-9BA1-48A9-B928-CA25FDD8F31F" ascii wide nocase
        $guid_A7AD39B5_9BA1_48A9_B928_CA25FDD8F31F_bin = { B5 39 AD A7 A1 9B A9 48 B9 28 CA 25 FD D8 F3 1F }

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_A8FE1F5C_6B2A_4417_907F_4F6EDE9C15A3_str = "A8FE1F5C-6B2A-4417-907F-4F6EDE9C15A3" ascii wide nocase
        $guid_A8FE1F5C_6B2A_4417_907F_4F6EDE9C15A3_bin = { 5C 1F FE A8 2A 6B 17 44 90 7F 4F 6E DE 9C 15 A3 }

        // Lockless allows for the copying of locked files.
        // https://github.com/GhostPack/Lockless
        $guid_A91421CB_7909_4383_BA43_C2992BBBAC22_str = "A91421CB-7909-4383-BA43-C2992BBBAC22" ascii wide nocase
        $guid_A91421CB_7909_4383_BA43_C2992BBBAC22_bin = { CB 21 14 A9 09 79 83 43 BA 43 C2 99 2B BB AC 22 }

        // prompt a user for credentials using a Windows credential dialog
        // https://github.com/ryanmrestivo/red-team/blob/1e53b7aa77717a22c9bd54facc64155a9a4c49fc/Exploitation-Tools/OffensiveCSharp/CredPhisher
        $guid_A9386992_CFAC_468A_BD41_78382212E5B9_str = "A9386992-CFAC-468A-BD41-78382212E5B9" ascii wide nocase
        $guid_A9386992_CFAC_468A_BD41_78382212E5B9_bin = { 92 69 38 A9 AC CF 8A 46 BD 41 78 38 22 12 E5 B9 }

        // Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // https://github.com/sfewer-r7/CVE-2023-27532
        $guid_A96C7C34_5791_43CF_9F8B_8EF5B3FB6EBA_str = "A96C7C34-5791-43CF-9F8B-8EF5B3FB6EBA" ascii wide nocase
        $guid_A96C7C34_5791_43CF_9F8B_8EF5B3FB6EBA_bin = { 34 7C 6C A9 91 57 CF 43 9F 8B 8E F5 B3 FB 6E BA }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_A9EAA820_EC72_4052_80D0_A2CCBFCC83E6_str = "A9EAA820-EC72-4052-80D0-A2CCBFCC83E6" ascii wide nocase
        $guid_A9EAA820_EC72_4052_80D0_A2CCBFCC83E6_bin = { 20 A8 EA A9 72 EC 52 40 80 D0 A2 CC BF CC 83 E6 }

        // SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // https://github.com/wh0amitz/SharpADWS
        $guid_AA488748_3D0E_4A52_8747_AB42A7143760_str = "AA488748-3D0E-4A52-8747-AB42A7143760" ascii wide nocase
        $guid_AA488748_3D0E_4A52_8747_AB42A7143760_bin = { 48 87 48 AA 0E 3D 52 4A 87 47 AB 42 A7 14 37 60 }

        // Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // https://github.com/bugch3ck/SharpEfsPotato
        $guid_AAB4D641_C310_4572_A9C2_6D12593AB28E_str = "AAB4D641-C310-4572-A9C2-6D12593AB28E" ascii wide nocase
        $guid_AAB4D641_C310_4572_A9C2_6D12593AB28E_bin = { 41 D6 B4 AA 10 C3 72 45 A9 C2 6D 12 59 3A B2 8E }

        // UAC bypass by abusing RPC and debug objects.
        // https://github.com/Kudaes/Elevator
        $guid_AAB75969_92BA_4632_9F78_AF52FA2BCE1E_str = "AAB75969-92BA-4632-9F78-AF52FA2BCE1E" ascii wide nocase
        $guid_AAB75969_92BA_4632_9F78_AF52FA2BCE1E_bin = { 69 59 B7 AA BA 92 32 46 9F 78 AF 52 FA 2B CE 1E }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_AB2E1440_7EC2_45A2_8CF3_2975DE8A57AD_str = "AB2E1440-7EC2-45A2-8CF3-2975DE8A57AD" ascii wide nocase
        $guid_AB2E1440_7EC2_45A2_8CF3_2975DE8A57AD_bin = { 40 14 2E AB C2 7E A2 45 8C F3 29 75 DE 8A 57 AD }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_AB6CDF36_F336_4F14_8D69_3C190B7DEC65_str = "AB6CDF36-F336-4F14-8D69-3C190B7DEC65" ascii wide nocase
        $guid_AB6CDF36_F336_4F14_8D69_3C190B7DEC65_bin = { 36 DF 6C AB 36 F3 14 4F 8D 69 3C 19 0B 7D EC 65 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_AB850676_3744_4BFD_82FA_E21D19622BF9_str = "AB850676-3744-4BFD-82FA-E21D19622BF9" ascii wide nocase
        $guid_AB850676_3744_4BFD_82FA_E21D19622BF9_bin = { 76 06 85 AB 44 37 FD 4B 82 FA E2 1D 19 62 2B F9 }

        // stealing Windows tokens
        // https://github.com/decoder-it/TokenStealer
        $guid_ABC32DBD_B697_482D_A763_7BA82FE9CEA2_str = "ABC32DBD-B697-482D-A763-7BA82FE9CEA2" ascii wide nocase
        $guid_ABC32DBD_B697_482D_A763_7BA82FE9CEA2_bin = { BD 2D C3 AB 97 B6 2D 48 A7 63 7B A8 2F E9 CE A2 }

        // walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // https://github.com/malcomvetter/Periscope
        $guid_ABF5940C_60AC_4892_B3F0_0F9262C550B3_str = "ABF5940C-60AC-4892-B3F0-0F9262C550B3" ascii wide nocase
        $guid_ABF5940C_60AC_4892_B3F0_0F9262C550B3_bin = { 0C 94 F5 AB AC 60 92 48 B3 F0 0F 92 62 C5 50 B3 }

        // C++ stealer (passwords - cookies - forms - cards - wallets) 
        // https://github.com/SecUser1/Necro-Stealer
        $guid_ac3107cf_291c_449b_9121_55cd37f6383e_str = "ac3107cf-291c-449b-9121-55cd37f6383e" ascii wide nocase
        $guid_ac3107cf_291c_449b_9121_55cd37f6383e_bin = { CF 07 31 AC 1C 29 9B 44 91 21 55 CD 37 F6 38 3E }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_ACEE9097_0CA8_4520_A6CA_3BF97B7A86DE_str = "ACEE9097-0CA8-4520-A6CA-3BF97B7A86DE" ascii wide nocase
        $guid_ACEE9097_0CA8_4520_A6CA_3BF97B7A86DE_bin = { 97 90 EE AC A8 0C 20 45 A6 CA 3B F9 7B 7A 86 DE }

        // Get file less command execution for Lateral Movement.
        // https://github.com/juliourena/SharpNoPSExec
        $guid_acf7a8a9_3aaf_46c2_8aa8_2d12d7681baf_str = "acf7a8a9-3aaf-46c2-8aa8-2d12d7681baf" ascii wide nocase
        $guid_acf7a8a9_3aaf_46c2_8aa8_2d12d7681baf_bin = { A9 A8 F7 AC AF 3A C2 46 8A A8 2D 12 D7 68 1B AF }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_AD0067D9_4AF6_47C2_B0C3_D768A9624002_str = "AD0067D9-4AF6-47C2-B0C3-D768A9624002" ascii wide nocase
        $guid_AD0067D9_4AF6_47C2_B0C3_D768A9624002_bin = { D9 67 00 AD F6 4A C2 47 B0 C3 D7 68 A9 62 40 02 }

        // Tool for viewing NTDS.dit
        // https://github.com/trustedsec/DitExplorer
        $guid_AD240C26_717F_4937_A4CD_5827BDC315E6_str = "AD240C26-717F-4937-A4CD-5827BDC315E6" ascii wide nocase
        $guid_AD240C26_717F_4937_A4CD_5827BDC315E6_bin = { 26 0C 24 AD 7F 71 37 49 A4 CD 58 27 BD C3 15 E6 }

        // proof-of-concept of Process Forking.
        // https://github.com/D4stiny/ForkPlayground
        $guid_AD495F95_007A_4DC1_9481_0689CA0547D9_str = "AD495F95-007A-4DC1-9481-0689CA0547D9" ascii wide nocase
        $guid_AD495F95_007A_4DC1_9481_0689CA0547D9_bin = { 95 5F 49 AD 7A 00 C1 4D 94 81 06 89 CA 05 47 D9 }

        // PEASS-ng - Privilege Escalation Awesome Scripts suite
        // https://github.com/peass-ng/PEASS-ng
        $guid_AD9F3A60_C492_4823_8F24_6F4854E7CBF5_str = "AD9F3A60-C492-4823-8F24-6F4854E7CBF5" ascii wide nocase
        $guid_AD9F3A60_C492_4823_8F24_6F4854E7CBF5_bin = { 60 3A 9F AD 92 C4 23 48 8F 24 6F 48 54 E7 CB F5 }

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_ADCEEFBA_CE43_4239_8AE8_7D8D43E66BB1_str = "ADCEEFBA-CE43-4239-8AE8-7D8D43E66BB1" ascii wide nocase
        $guid_ADCEEFBA_CE43_4239_8AE8_7D8D43E66BB1_bin = { BA EF CE AD 43 CE 39 42 8A E8 7D 8D 43 E6 6B B1 }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_AE81B416_FBC4_4F88_9EFC_D07D8789355F_str = "AE81B416-FBC4-4F88-9EFC-D07D8789355F" ascii wide nocase
        $guid_AE81B416_FBC4_4F88_9EFC_D07D8789355F_bin = { 16 B4 81 AE C4 FB 88 4F 9E FC D0 7D 87 89 35 5F }

        // SharpWeb - to export browser data including passwords - history - cookies - bookmarks and download records
        // https://github.com/StarfireLab/SharpWeb
        $guid_AE844C23_294E_4690_8CF3_2E5F9769D8E0_str = "AE844C23-294E-4690-8CF3-2E5F9769D8E0" ascii wide nocase
        $guid_AE844C23_294E_4690_8CF3_2E5F9769D8E0_bin = { 23 4C 84 AE 4E 29 90 46 8C F3 2E 5F 97 69 D8 E0 }

        // Tool for viewing NTDS.dit
        // https://github.com/trustedsec/DitExplorer
        $guid_AEC0EBBA_3BE4_4B5C_8F5C_0BB8DDDA7148_str = "AEC0EBBA-3BE4-4B5C-8F5C-0BB8DDDA7148" ascii wide nocase
        $guid_AEC0EBBA_3BE4_4B5C_8F5C_0BB8DDDA7148_bin = { BA EB C0 AE E4 3B 5C 4B 8F 5C 0B B8 DD DA 71 48 }

        // Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // https://github.com/GhostPack/Seatbelt
        $guid_AEC32155_D589_4150_8FE7_2900DF4554C8_str = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii wide nocase
        $guid_AEC32155_D589_4150_8FE7_2900DF4554C8_bin = { 55 21 C3 AE 89 D5 50 41 8F E7 29 00 DF 45 54 C8 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_aef6547e_3822_4f96_9708_bcf008129b2b_str = "aef6547e-3822-4f96-9708-bcf008129b2b" ascii wide nocase
        $guid_aef6547e_3822_4f96_9708_bcf008129b2b_bin = { 7E 54 F6 AE 22 38 96 4F 97 08 BC F0 08 12 9B 2B }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_AF0885E4_9E3B_49CA_9F13_0F869E8BF89D_str = "AF0885E4-9E3B-49CA-9F13-0F869E8BF89D" ascii wide nocase
        $guid_AF0885E4_9E3B_49CA_9F13_0F869E8BF89D_bin = { E4 85 08 AF 3B 9E CA 49 9F 13 0F 86 9E 8B F8 9D }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_AF10B9C3_7969_4971_BD7A_5C50D8D2547F_str = "AF10B9C3-7969-4971-BD7A-5C50D8D2547F" ascii wide nocase
        $guid_AF10B9C3_7969_4971_BD7A_5C50D8D2547F_bin = { C3 B9 10 AF 69 79 71 49 BD 7A 5C 50 D8 D2 54 7F }

        // Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // https://github.com/trustedsec/specula
        $guid_AF2D318C_2C5A_4C9D_BE4C_AA5B3E8037DB_str = "AF2D318C-2C5A-4C9D-BE4C-AA5B3E8037DB" ascii wide nocase
        $guid_AF2D318C_2C5A_4C9D_BE4C_AA5B3E8037DB_bin = { 8C 31 2D AF 5A 2C 9D 4C BE 4C AA 5B 3E 80 37 DB }

        // walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // https://github.com/malcomvetter/Periscope
        $guid_AF7F4404_C746_43EC_86EA_8405473C95C9_str = "AF7F4404-C746-43EC-86EA-8405473C95C9" ascii wide nocase
        $guid_AF7F4404_C746_43EC_86EA_8405473C95C9_bin = { 04 44 7F AF 46 C7 EC 43 86 EA 84 05 47 3C 95 C9 }

        // A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // https://github.com/med0x2e/GadgetToJScript
        $guid_AF9C62A1_F8D2_4BE0_B019_0A7873E81EA9_str = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" ascii wide nocase
        $guid_AF9C62A1_F8D2_4BE0_B019_0A7873E81EA9_bin = { A1 62 9C AF D2 F8 E0 4B B0 19 0A 78 73 E8 1E A9 }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_AFB848D0_68F8_42D1_A1C8_99DFBE034FCF_str = "AFB848D0-68F8-42D1-A1C8-99DFBE034FCF" ascii wide nocase
        $guid_AFB848D0_68F8_42D1_A1C8_99DFBE034FCF_bin = { D0 48 B8 AF F8 68 D1 42 A1 C8 99 DF BE 03 4F CF }

        // similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // https://github.com/CICADA8-Research/RemoteKrbRelay
        $guid_B00DC126_D32B_429F_9BB5_97AF33BEE0E1_str = "B00DC126-D32B-429F-9BB5-97AF33BEE0E1" ascii wide nocase
        $guid_B00DC126_D32B_429F_9BB5_97AF33BEE0E1_bin = { 26 C1 0D B0 2B D3 9F 42 9B B5 97 AF 33 BE E0 E1 }

        // RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // https://github.com/antonioCoco/RogueWinRM
        $guid_B03A3AF9_9448_43FE_8CEE_5A2C43BFAC86_str = "B03A3AF9-9448-43FE-8CEE-5A2C43BFAC86" ascii wide nocase
        $guid_B03A3AF9_9448_43FE_8CEE_5A2C43BFAC86_bin = { F9 3A 3A B0 48 94 FE 43 8C EE 5A 2C 43 BF AC 86 }

        // Bypassing EDR Solutions
        // https://github.com/helviojunior/hookchain
        $guid_B0C08C11_23C4_495F_B40B_14066F12FAAB_str = "B0C08C11-23C4-495F-B40B-14066F12FAAB" ascii wide nocase
        $guid_B0C08C11_23C4_495F_B40B_14066F12FAAB_bin = { 11 8C C0 B0 C4 23 5F 49 B4 0B 14 06 6F 12 FA AB }

        // Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // https://x.com/0gtweet/status/1817859483445461406
        $guid_b10cfda1_f24f_441b_8f43_80cb93e786ec_str = "b10cfda1-f24f-441b-8f43-80cb93e786ec" ascii wide nocase
        $guid_b10cfda1_f24f_441b_8f43_80cb93e786ec_bin = { A1 FD 0C B1 4F F2 1B 44 8F 43 80 CB 93 E7 86 EC }

        // open source ransomware - many variant in the wild
        // https://github.com/goliate/hidden-tear
        $guid_B138FFBA_1076_4B58_8A98_67B34E8A7C5C_str = "B138FFBA-1076-4B58-8A98-67B34E8A7C5C" ascii wide nocase
        $guid_B138FFBA_1076_4B58_8A98_67B34E8A7C5C_bin = { BA FF 38 B1 76 10 58 4B 8A 98 67 B3 4E 8A 7C 5C }

        // A C# Command & Control framework
        // https://github.com/DragoQCC/HardHatC2
        $guid_B1865FC0_5605_4587_9FCB_8B9DF6B5C6B1_str = "B1865FC0-5605-4587-9FCB-8B9DF6B5C6B1" ascii wide nocase
        $guid_B1865FC0_5605_4587_9FCB_8B9DF6B5C6B1_bin = { C0 5F 86 B1 05 56 87 45 9F CB 8B 9D F6 B5 C6 B1 }

        // binary padding to add junk data and change the on-disk representation of a file
        // https://github.com/mertdas/SharpIncrease
        $guid_B19E7FDE_C2CB_4C0A_9C5E_DFC73ADDB5C0_str = "B19E7FDE-C2CB-4C0A-9C5E-DFC73ADDB5C0" ascii wide nocase
        $guid_B19E7FDE_C2CB_4C0A_9C5E_DFC73ADDB5C0_bin = { DE 7F 9E B1 CB C2 0A 4C 9C 5E DF C7 3A DD B5 C0 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_B1CB9A30_FEA6_4467_BEC5_4803CCE9BF78_str = "B1CB9A30-FEA6-4467-BEC5-4803CCE9BF78" ascii wide nocase
        $guid_B1CB9A30_FEA6_4467_BEC5_4803CCE9BF78_bin = { 30 9A CB B1 A6 FE 67 44 BE C5 48 03 CC E9 BF 78 }

        // EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // https://github.com/Mattiwatti/EfiGuard
        $guid_B2924789_9912_4B6F_8F7B_53240AC3BA0E_str = "B2924789-9912-4B6F-8F7B-53240AC3BA0E" ascii wide nocase
        $guid_B2924789_9912_4B6F_8F7B_53240AC3BA0E_bin = { 89 47 92 B2 12 99 6F 4B 8F 7B 53 24 0A C3 BA 0E }

        // Tunnel TCP connections through a file
        // https://github.com/fiddyschmitt/File-Tunnel
        $guid_B2B4238B_1055_4679_B7D5_7CCE2397098E_str = "B2B4238B-1055-4679-B7D5-7CCE2397098E" ascii wide nocase
        $guid_B2B4238B_1055_4679_B7D5_7CCE2397098E_bin = { 8B 23 B4 B2 55 10 79 46 B7 D5 7C CE 23 97 09 8E }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_B2D22DC6_1CA5_4CE3_9756_3673336705FB_str = "B2D22DC6-1CA5-4CE3-9756-3673336705FB" ascii wide nocase
        $guid_B2D22DC6_1CA5_4CE3_9756_3673336705FB_bin = { C6 2D D2 B2 A5 1C E3 4C 97 56 36 73 33 67 05 FB }

        // inspect token information
        // https://github.com/daem0nc0re/PrivFu
        $guid_B35266FB_81FD_4671_BF1D_CE6AEF8B8D64_str = "B35266FB-81FD-4671-BF1D-CE6AEF8B8D64" ascii wide nocase
        $guid_B35266FB_81FD_4671_BF1D_CE6AEF8B8D64_bin = { FB 66 52 B3 FD 81 71 46 BF 1D CE 6A EF 8B 8D 64 }

        // Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // https://github.com/Idov31/Sandman
        $guid_B362EC25_70BD_4E6C_9744_173D20FDA392_str = "B362EC25-70BD-4E6C-9744-173D20FDA392" ascii wide nocase
        $guid_B362EC25_70BD_4E6C_9744_173D20FDA392_bin = { 25 EC 62 B3 BD 70 6C 4E 97 44 17 3D 20 FD A3 92 }

        // An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // https://github.com/eladshamir/BadWindowsService
        $guid_B474B962_A46B_4D35_86F3_E8BA120C88C0_str = "B474B962-A46B-4D35-86F3-E8BA120C88C0" ascii wide nocase
        $guid_B474B962_A46B_4D35_86F3_E8BA120C88C0_bin = { 62 B9 74 B4 6B A4 35 4D 86 F3 E8 BA 12 0C 88 C0 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_B5205EBA_EC32_4C53_86A0_FAEEE7393EC0_str = "B5205EBA-EC32-4C53-86A0-FAEEE7393EC0" ascii wide nocase
        $guid_B5205EBA_EC32_4C53_86A0_FAEEE7393EC0_bin = { BA 5E 20 B5 32 EC 53 4C 86 A0 FA EE E7 39 3E C0 }

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_B52E2D10_A94A_4605_914A_2DCEF6A757EF_str = "B52E2D10-A94A-4605-914A-2DCEF6A757EF" ascii wide nocase
        $guid_B52E2D10_A94A_4605_914A_2DCEF6A757EF_bin = { 10 2D 2E B5 4A A9 05 46 91 4A 2D CE F6 A7 57 EF }

        // Abuses the Windows containers framework to bypass EDRs.
        // https://github.com/deepinstinct/ContainYourself
        $guid_B5627919_4DFB_49C6_AC1B_C757F4B4A103_str = "B5627919-4DFB-49C6-AC1B-C757F4B4A103" ascii wide nocase
        $guid_B5627919_4DFB_49C6_AC1B_C757F4B4A103_bin = { 19 79 62 B5 FB 4D C6 49 AC 1B C7 57 F4 B4 A1 03 }

        // Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // https://github.com/trustedsec/specula
        $guid_B58767EE_5185_4E99_818F_6285332400E6_str = "B58767EE-5185-4E99-818F-6285332400E6" ascii wide nocase
        $guid_B58767EE_5185_4E99_818F_6285332400E6_bin = { EE 67 87 B5 85 51 99 4E 81 8F 62 85 33 24 00 E6 }

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_B59C7741_D522_4A41_BF4D_9BADDDEBB84A_str = "B59C7741-D522-4A41-BF4D-9BADDDEBB84A" ascii wide nocase
        $guid_B59C7741_D522_4A41_BF4D_9BADDDEBB84A_bin = { 41 77 9C B5 22 D5 41 4A BF 4D 9B AD DD EB B8 4A }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_B5C5BDD1_568E_44F6_91FF_B26962AF9A6C_str = "B5C5BDD1-568E-44F6-91FF-B26962AF9A6C" ascii wide nocase
        $guid_B5C5BDD1_568E_44F6_91FF_B26962AF9A6C_bin = { D1 BD C5 B5 8E 56 F6 44 91 FF B2 69 62 AF 9A 6C }

        // A native backdoor module for Microsoft IIS
        // https://github.com/0x09AL/IIS-Raid
        $guid_B5E39D15_9678_474A_9838_4C720243968B_str = "B5E39D15-9678-474A-9838-4C720243968B" ascii wide nocase
        $guid_B5E39D15_9678_474A_9838_4C720243968B_bin = { 15 9D E3 B5 78 96 4A 47 98 38 4C 72 02 43 96 8B }

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_B651A53C_FAE6_482E_A590_CA3B48B7F384_str = "B651A53C-FAE6-482E-A590-CA3B48B7F384" ascii wide nocase
        $guid_B651A53C_FAE6_482E_A590_CA3B48B7F384_bin = { 3C A5 51 B6 E6 FA 2E 48 A5 90 CA 3B 48 B7 F3 84 }

        // Abusing Impersonation Privileges on Windows 10 and Server 2019
        // https://github.com/itm4n/PrintSpoofer
        $guid_B67143DE_321D_4034_AC1D_C6BB2D98563F_str = "B67143DE-321D-4034-AC1D-C6BB2D98563F" ascii wide nocase
        $guid_B67143DE_321D_4034_AC1D_C6BB2D98563F_bin = { DE 43 71 B6 1D 32 34 40 AC 1D C6 BB 2D 98 56 3F }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_B672DE08_269D_4AA6_8535_D3BC59BB086B_str = "B672DE08-269D-4AA6-8535-D3BC59BB086B" ascii wide nocase
        $guid_B672DE08_269D_4AA6_8535_D3BC59BB086B_bin = { 08 DE 72 B6 9D 26 A6 4A 85 35 D3 BC 59 BB 08 6B }

        // Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // https://github.com/gitjdm/dumper2020
        $guid_B7355478_EEE0_46A7_807A_23CF0C5295AE_str = "B7355478-EEE0-46A7-807A-23CF0C5295AE" ascii wide nocase
        $guid_B7355478_EEE0_46A7_807A_23CF0C5295AE_bin = { 78 54 35 B7 E0 EE A7 46 80 7A 23 CF 0C 52 95 AE }

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_B7C64002_5002_410F_868C_826073AFA924_str = "B7C64002-5002-410F-868C-826073AFA924" ascii wide nocase
        $guid_B7C64002_5002_410F_868C_826073AFA924_bin = { 02 40 C6 B7 02 50 0F 41 86 8C 82 60 73 AF A9 24 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_B7FF0EE8_6C68_46C6_AADB_58C0E3309FB2_str = "B7FF0EE8-6C68-46C6-AADB-58C0E3309FB2" ascii wide nocase
        $guid_B7FF0EE8_6C68_46C6_AADB_58C0E3309FB2_bin = { E8 0E FF B7 68 6C C6 46 AA DB 58 C0 E3 30 9F B2 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_B84EFDD8_CEA0_4CCA_B7B8_3F8AB3A336B4_str = "B84EFDD8-CEA0-4CCA-B7B8-3F8AB3A336B4" ascii wide nocase
        $guid_B84EFDD8_CEA0_4CCA_B7B8_3F8AB3A336B4_bin = { D8 FD 4E B8 A0 CE CA 4C B7 B8 3F 8A B3 A3 36 B4 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_B87A5373_750C_44A7_BCEC_32185A3077AC_str = "B87A5373-750C-44A7-BCEC-32185A3077AC" ascii wide nocase
        $guid_B87A5373_750C_44A7_BCEC_32185A3077AC_bin = { 73 53 7A B8 0C 75 A7 44 BC EC 32 18 5A 30 77 AC }

        // Windows Privilege Escalation from User to Domain Admin.
        // https://github.com/antonioCoco/RemotePotato0
        $guid_B88B65D3_2689_4E39_892C_7532087174CB_str = "B88B65D3-2689-4E39-892C-7532087174CB" ascii wide nocase
        $guid_B88B65D3_2689_4E39_892C_7532087174CB_bin = { D3 65 8B B8 89 26 39 4E 89 2C 75 32 08 71 74 CB }

        // Patching signtool.exe to accept expired certificates for code-signing
        // https://github.com/hackerhouse-opensource/SignToolEx
        $guid_B8AEE3F1_0642_443C_B42C_33BADCD42365_str = "B8AEE3F1-0642-443C-B42C-33BADCD42365" ascii wide nocase
        $guid_B8AEE3F1_0642_443C_B42C_33BADCD42365_bin = { F1 E3 AE B8 42 06 3C 44 B4 2C 33 BA DC D4 23 65 }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_B8FF9629_B4CE_4871_A2CD_8E6D73F6DF9E_str = "B8FF9629-B4CE-4871-A2CD-8E6D73F6DF9E" ascii wide nocase
        $guid_B8FF9629_B4CE_4871_A2CD_8E6D73F6DF9E_bin = { 29 96 FF B8 CE B4 71 48 A2 CD 8E 6D 73 F6 DF 9E }

        // Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // https://github.com/ricardojoserf/TrickDump
        $guid_B92B6B67_C7C8_4548_85EE_A215D74C000D_str = "B92B6B67-C7C8-4548-85EE-A215D74C000D" ascii wide nocase
        $guid_B92B6B67_C7C8_4548_85EE_A215D74C000D_bin = { 67 6B 2B B9 C8 C7 48 45 85 EE A2 15 D7 4C 00 0D }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_B9635D08_2BB2_404B_92B7_6A4981CB34F3_str = "B9635D08-2BB2-404B-92B7-6A4981CB34F3" ascii wide nocase
        $guid_B9635D08_2BB2_404B_92B7_6A4981CB34F3_bin = { 08 5D 63 B9 B2 2B 4B 40 92 B7 6A 49 81 CB 34 F3 }

        // A Combination LSASS Dumper and LSASS Parser
        // https://github.com/icyguider/DumpNParse
        $guid_BA1F3992_9654_4424_A0CC_26158FDFBF74_str = "BA1F3992-9654-4424-A0CC-26158FDFBF74" ascii wide nocase
        $guid_BA1F3992_9654_4424_A0CC_26158FDFBF74_bin = { 92 39 1F BA 54 96 24 44 A0 CC 26 15 8F DF BF 74 }

        // Cross-platform multi-protocol VPN software abused by attackers
        // https://github.com/SoftEtherVPN/SoftEtherVPN
        $guid_BA902FC8_E936_44AA_9C88_57D358BBB700_str = "BA902FC8-E936-44AA-9C88-57D358BBB700" ascii wide nocase
        $guid_BA902FC8_E936_44AA_9C88_57D358BBB700_bin = { C8 2F 90 BA 36 E9 AA 44 9C 88 57 D3 58 BB B7 00 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_BA9D2748_1342_41A3_87F2_343E82D99813_str = "BA9D2748-1342-41A3-87F2-343E82D99813" ascii wide nocase
        $guid_BA9D2748_1342_41A3_87F2_343E82D99813_bin = { 48 27 9D BA 42 13 A3 41 87 F2 34 3E 82 D9 98 13 }

        // Stealthy Stand Alone PHP Web Shell
        // https://github.com/SpiderMate/Jatayu
        $guid_bb3b1a1f_0447_42a6_955a_88681fb88499_str = "bb3b1a1f-0447-42a6-955a-88681fb88499" ascii wide nocase
        $guid_bb3b1a1f_0447_42a6_955a_88681fb88499_bin = { 1F 1A 3B BB 47 04 A6 42 95 5A 88 68 1F B8 84 99 }

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_BB8A69C4_18B0_4FF2_989C_F70778FFBCE6_str = "BB8A69C4-18B0-4FF2-989C-F70778FFBCE6" ascii wide nocase
        $guid_BB8A69C4_18B0_4FF2_989C_F70778FFBCE6_bin = { C4 69 8A BB B0 18 F2 4F 98 9C F7 07 78 FF BC E6 }

        // bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // https://github.com/undergroundwires/privacy.sexy
        $guid_bba575ec_0c7f_42e1_9b59_b7c9cca522ba_str = "bba575ec-0c7f-42e1-9b59-b7c9cca522ba" ascii wide nocase
        $guid_bba575ec_0c7f_42e1_9b59_b7c9cca522ba_bin = { EC 75 A5 BB 7F 0C E1 42 9B 59 B7 C9 CC A5 22 BA }

        // tool to authenticate to an LDAP/S server with a certificate through Schannel
        // https://github.com/AlmondOffSec/PassTheCert
        $guid_BBCD0202_C086_437C_A606_015456F90C46_str = "BBCD0202-C086-437C-A606-015456F90C46" ascii wide nocase
        $guid_BBCD0202_C086_437C_A606_015456F90C46_bin = { 02 02 CD BB 86 C0 7C 43 A6 06 01 54 56 F9 0C 46 }

        // PrintNightmare exploitation
        // https://vx-underground.org/Archive/Dispossessor%20Leaks
        $guid_BBFBAF1D_A01E_4615_A208_786147320C20_str = "BBFBAF1D-A01E-4615-A208-786147320C20" ascii wide nocase
        $guid_BBFBAF1D_A01E_4615_A208_786147320C20_bin = { 1D AF FB BB 1E A0 15 46 A2 08 78 61 47 32 0C 20 }

        // similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // https://github.com/CICADA8-Research/RemoteKrbRelay
        $guid_BC74B071_B36A_4EE8_8F03_5CF0A02C32DA_str = "BC74B071-B36A-4EE8-8F03-5CF0A02C32DA" ascii wide nocase
        $guid_BC74B071_B36A_4EE8_8F03_5CF0A02C32DA_bin = { 71 B0 74 BC 6A B3 E8 4E 8F 03 5C F0 A0 2C 32 DA }

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_BC9BC3C3_4FBC_4F36_866C_AC2B4758BEBE_str = "BC9BC3C3-4FBC-4F36-866C-AC2B4758BEBE" ascii wide nocase
        $guid_BC9BC3C3_4FBC_4F36_866C_AC2B4758BEBE_bin = { C3 C3 9B BC BC 4F 36 4F 86 6C AC 2B 47 58 BE BE }

        // Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // https://github.com/Hackcraft-Labs/SharpShares
        $guid_BCBC884D_2D47_4138_B68F_7D425C9291F9_str = "BCBC884D-2D47-4138-B68F-7D425C9291F9" ascii wide nocase
        $guid_BCBC884D_2D47_4138_B68F_7D425C9291F9_bin = { 4D 88 BC BC 47 2D 38 41 B6 8F 7D 42 5C 92 91 F9 }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_BCE48DAE_232E_4B3D_B5B5_D0B29BB7E9DE_str = "BCE48DAE-232E-4B3D-B5B5-D0B29BB7E9DE" ascii wide nocase
        $guid_BCE48DAE_232E_4B3D_B5B5_D0B29BB7E9DE_bin = { AE 8D E4 BC 2E 23 3D 4B B5 B5 D0 B2 9B B7 E9 DE }

        // ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // https://github.com/GhostPack/ForgeCert
        $guid_bd346689_8ee6_40b3_858b_4ed94f08d40a_str = "bd346689-8ee6-40b3-858b-4ed94f08d40a" ascii wide nocase
        $guid_bd346689_8ee6_40b3_858b_4ed94f08d40a_bin = { 89 66 34 BD E6 8E B3 40 85 8B 4E D9 4F 08 D4 0A }

        // A sharpen version of CrackMapExec
        // https://github.com/cube0x0/SharpMapExec
        $guid_BD5220F7_E1FB_41D2_91EC_E4C50C6E9B9F_str = "BD5220F7-E1FB-41D2-91EC-E4C50C6E9B9F" ascii wide nocase
        $guid_BD5220F7_E1FB_41D2_91EC_E4C50C6E9B9F_bin = { F7 20 52 BD FB E1 D2 41 91 EC E4 C5 0C 6E 9B 9F }

        // Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // https://github.com/TheD1rkMtr/D1rkInject
        $guid_BD602C80_47ED_4294_B981_0119D2200DB8_str = "BD602C80-47ED-4294-B981-0119D2200DB8" ascii wide nocase
        $guid_BD602C80_47ED_4294_B981_0119D2200DB8_bin = { 80 2C 60 BD ED 47 94 42 B9 81 01 19 D2 20 0D B8 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_BD628EE4_F3A0_4242_BCE3_95CA21114CD7_str = "BD628EE4-F3A0-4242-BCE3-95CA21114CD7" ascii wide nocase
        $guid_BD628EE4_F3A0_4242_BCE3_95CA21114CD7_bin = { E4 8E 62 BD A0 F3 42 42 BC E3 95 CA 21 11 4C D7 }

        // RedPersist is a Windows Persistence tool written in C#
        // https://github.com/mertdas/RedPersist
        $guid_BD745A5E_A1E9_4FDD_A15B_E9F303A625AE_str = "BD745A5E-A1E9-4FDD-A15B-E9F303A625AE" ascii wide nocase
        $guid_BD745A5E_A1E9_4FDD_A15B_E9F303A625AE_bin = { 5E 5A 74 BD E9 A1 DD 4F A1 5B E9 F3 03 A6 25 AE }

        // RedPersist is a Windows Persistence tool written in C#
        // https://github.com/mertdas/RedPersist
        $guid_bd745a5e_a1e9_4fdd_a15b_e9f303a625ae_str = "bd745a5e-a1e9-4fdd-a15b-e9f303a625ae" ascii wide nocase
        $guid_bd745a5e_a1e9_4fdd_a15b_e9f303a625ae_bin = { 5E 5A 74 BD E9 A1 DD 4F A1 5B E9 F3 03 A6 25 AE }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_BDED2735_F9E4_4B2E_9636_4EEDD78FC720_str = "BDED2735-F9E4-4B2E-9636-4EEDD78FC720" ascii wide nocase
        $guid_BDED2735_F9E4_4B2E_9636_4EEDD78FC720_bin = { 35 27 ED BD E4 F9 2E 4B 96 36 4E ED D7 8F C7 20 }

        // Checks for the presence of known defensive products such as AV/EDR and logging tools
        // https://github.com/PwnDexter/SharpEDRChecker
        $guid_BDFEE233_3FED_42E5_AA64_492EB2AC7047_str = "BDFEE233-3FED-42E5-AA64-492EB2AC7047" ascii wide nocase
        $guid_BDFEE233_3FED_42E5_AA64_492EB2AC7047_bin = { 33 E2 FE BD ED 3F E5 42 AA 64 49 2E B2 AC 70 47 }

        // Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // https://github.com/mgeeky/ProtectMyTooling
        $guid_be642266_f34d_43c3_b6e4_eebf8e489519_str = "be642266-f34d-43c3-b6e4-eebf8e489519" ascii wide nocase
        $guid_be642266_f34d_43c3_b6e4_eebf8e489519_bin = { 66 22 64 BE 4D F3 C3 43 B6 E4 EE BF 8E 48 95 19 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_BE801141_0D4D_4950_85C8_8E93C9D3312F_str = "BE801141-0D4D-4950-85C8-8E93C9D3312F" ascii wide nocase
        $guid_BE801141_0D4D_4950_85C8_8E93C9D3312F_bin = { 41 11 80 BE 4D 0D 50 49 85 C8 8E 93 C9 D3 31 2F }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_BEB67A6E_4C54_4DE5_8C6B_2C12F44A7B92_str = "BEB67A6E-4C54-4DE5-8C6B-2C12F44A7B92" ascii wide nocase
        $guid_BEB67A6E_4C54_4DE5_8C6B_2C12F44A7B92_bin = { 6E 7A B6 BE 54 4C E5 4D 8C 6B 2C 12 F4 4A 7B 92 }

        // Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // https://github.com/0x09AL/RdpThief
        $guid_BEBE6A01_0C03_4A7C_8FE9_9285F01C0B03_str = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" ascii wide nocase
        $guid_BEBE6A01_0C03_4A7C_8FE9_9285F01C0B03_bin = { 01 6A BE BE 03 0C 7C 4A 8F E9 92 85 F0 1C 0B 03 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_BEE88186_769A_452C_9DD9_D0E0815D92BF_str = "BEE88186-769A-452C-9DD9-D0E0815D92BF" ascii wide nocase
        $guid_BEE88186_769A_452C_9DD9_D0E0815D92BF_bin = { 86 81 E8 BE 9A 76 2C 45 9D D9 D0 E0 81 5D 92 BF }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_BF45108E_1E43_486B_A71D_5426BBB041DB_str = "BF45108E-1E43-486B-A71D-5426BBB041DB" ascii wide nocase
        $guid_BF45108E_1E43_486B_A71D_5426BBB041DB_bin = { 8E 10 45 BF 43 1E 6B 48 A7 1D 54 26 BB B0 41 DB }

        // bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // https://github.com/undergroundwires/privacy.sexy
        $guid_c06bb3f0_cbdc_4384_84cf_21b7fe6dfe01_str = "c06bb3f0-cbdc-4384-84cf-21b7fe6dfe01" ascii wide nocase
        $guid_c06bb3f0_cbdc_4384_84cf_21b7fe6dfe01_bin = { F0 B3 6B C0 DC CB 84 43 84 CF 21 B7 FE 6D FE 01 }

        // Using the Counter Strike 1.6 RCON protocol as a C2 Channel
        // https://github.com/eversinc33/1.6-C2
        $guid_c07d3356_7f9b_45e0_a4f7_7b1487d966b8_str = "c07d3356-7f9b-45e0-a4f7-7b1487d966b8" ascii wide nocase
        $guid_c07d3356_7f9b_45e0_a4f7_7b1487d966b8_bin = { 56 33 7D C0 9B 7F E0 45 A4 F7 7B 14 87 D9 66 B8 }

        // SingleDose is a framework to build shellcode load/process injection techniques
        // https://github.com/Wra7h/SingleDose
        $guid_C0E67E76_1C78_4152_9F79_FA27B4F7CCCA_str = "C0E67E76-1C78-4152-9F79-FA27B4F7CCCA" ascii wide nocase
        $guid_C0E67E76_1C78_4152_9F79_FA27B4F7CCCA_bin = { 76 7E E6 C0 78 1C 52 41 9F 79 FA 27 B4 F7 CC CA }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_C10599E3_5A79_484F_940B_E4B61F256466_str = "C10599E3-5A79-484F-940B-E4B61F256466" ascii wide nocase
        $guid_C10599E3_5A79_484F_940B_E4B61F256466_bin = { E3 99 05 C1 79 5A 4F 48 94 0B E4 B6 1F 25 64 66 }

        // Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang
        // https://github.com/cyberark/kubesploit
        $guid_c1090dbc_f2f7_4d90_a241_86e0c0217786_str = "c1090dbc-f2f7-4d90-a241-86e0c0217786" ascii wide nocase
        $guid_c1090dbc_f2f7_4d90_a241_86e0c0217786_bin = { BC 0D 09 C1 F7 F2 90 4D A2 41 86 E0 C0 21 77 86 }

        // SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers
        // https://github.com/nccgroup/SCOMDecrypt
        $guid_C13C80ED_ED7A_4F27_93B1_DE6FD30A7B43_str = "C13C80ED-ED7A-4F27-93B1-DE6FD30A7B43" ascii wide nocase
        $guid_C13C80ED_ED7A_4F27_93B1_DE6FD30A7B43_bin = { ED 80 3C C1 7A ED 27 4F 93 B1 DE 6F D3 0A 7B 43 }

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_C23B51C4_2475_4FC6_9B3A_27D0A2B99B0F_str = "C23B51C4-2475-4FC6-9B3A-27D0A2B99B0F" ascii wide nocase
        $guid_C23B51C4_2475_4FC6_9B3A_27D0A2B99B0F_bin = { C4 51 3B C2 75 24 C6 4F 9B 3A 27 D0 A2 B9 9B 0F }

        // a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // https://github.com/zeze-zeze/NamedPipeMaster
        $guid_C2F24BBD_4807_49F5_B5E2_77FF0E8B756B_str = "C2F24BBD-4807-49F5-B5E2-77FF0E8B756B" ascii wide nocase
        $guid_C2F24BBD_4807_49F5_B5E2_77FF0E8B756B_bin = { BD 4B F2 C2 07 48 F5 49 B5 E2 77 FF 0E 8B 75 6B }

        // The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // https://github.com/sevagas/macro_pack
        $guid_C33A0993_A331_406C_83F5_9357DF239B30_str = "C33A0993-A331-406C-83F5-9357DF239B30" ascii wide nocase
        $guid_C33A0993_A331_406C_83F5_9357DF239B30_bin = { 93 09 3A C3 31 A3 6C 40 83 F5 93 57 DF 23 9B 30 }

        // linikatz is a tool to attack AD on UNIX
        // https://github.com/CiscoCXSecurity/linikatz
        $guid_C34208EA_8C33_473D_A9B4_53FB40347EA0_str = "C34208EA-8C33-473D-A9B4-53FB40347EA0" ascii wide nocase
        $guid_C34208EA_8C33_473D_A9B4_53FB40347EA0_bin = { EA 08 42 C3 33 8C 3D 47 A9 B4 53 FB 40 34 7E A0 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_C346B912_51F2_4A2E_ACC3_0AC2D28920C6_str = "C346B912-51F2-4A2E-ACC3-0AC2D28920C6" ascii wide nocase
        $guid_C346B912_51F2_4A2E_ACC3_0AC2D28920C6_bin = { 12 B9 46 C3 F2 51 2E 4A AC C3 0A C2 D2 89 20 C6 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_C373A937_312C_4C8D_BD04_BAAF568337E7_str = "C373A937-312C-4C8D-BD04-BAAF568337E7" ascii wide nocase
        $guid_C373A937_312C_4C8D_BD04_BAAF568337E7_bin = { 37 A9 73 C3 2C 31 8D 4C BD 04 BA AF 56 83 37 E7 }

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_C37637FC_3792_4354_8F5B_7E319E4E5A6D_str = "C37637FC-3792-4354-8F5B-7E319E4E5A6D" ascii wide nocase
        $guid_C37637FC_3792_4354_8F5B_7E319E4E5A6D_bin = { FC 37 76 C3 92 37 54 43 8F 5B 7E 31 9E 4E 5A 6D }

        // Open-Source Remote Administration Tool For Windows C# (RAT)
        // https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $guid_C3C49F45_2589_4E04_9C50_71B6035C14AE_str = "C3C49F45-2589-4E04-9C50-71B6035C14AE" ascii wide nocase
        $guid_C3C49F45_2589_4E04_9C50_71B6035C14AE_bin = { 45 9F C4 C3 89 25 04 4E 9C 50 71 B6 03 5C 14 AE }

        // Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // https://github.com/ricardojoserf/NativeBypassCredGuard
        $guid_c4d31433_5017_4b5e_956b_8a540520986c_str = "c4d31433-5017-4b5e-956b-8a540520986c" ascii wide nocase
        $guid_c4d31433_5017_4b5e_956b_8a540520986c_bin = { 33 14 D3 C4 17 50 5E 4B 95 6B 8A 54 05 20 98 6C }

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_C526B877_6AFF_413C_BC03_1837FB63BC22_str = "C526B877-6AFF-413C-BC03-1837FB63BC22" ascii wide nocase
        $guid_C526B877_6AFF_413C_BC03_1837FB63BC22_bin = { 77 B8 26 C5 FF 6A 3C 41 BC 03 18 37 FB 63 BC 22 }

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_C5C6F4EA_7F09_4AC7_AC2A_1246302B9856_str = "C5C6F4EA-7F09-4AC7-AC2A-1246302B9856" ascii wide nocase
        $guid_C5C6F4EA_7F09_4AC7_AC2A_1246302B9856_bin = { EA F4 C6 C5 09 7F C7 4A AC 2A 12 46 30 2B 98 56 }

        // Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // https://github.com/ricardojoserf/TrickDump
        $guid_C666C98C_84C3_4A5A_A73B_2FC711CFCB7F_str = "C666C98C-84C3-4A5A-A73B-2FC711CFCB7F" ascii wide nocase
        $guid_C666C98C_84C3_4A5A_A73B_2FC711CFCB7F_bin = { 8C C9 66 C6 C3 84 5A 4A A7 3B 2F C7 11 CF CB 7F }

        // Remote Command Executor: A OSS replacement for PsExec and RunAs
        // https://github.com/kavika13/RemCom
        $guid_C7038612_8183_67A7_8A9C_1379C2674156_str = "C7038612-8183-67A7-8A9C-1379C2674156" ascii wide nocase
        $guid_C7038612_8183_67A7_8A9C_1379C2674156_bin = { 12 86 03 C7 83 81 A7 67 8A 9C 13 79 C2 67 41 56 }

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_c708b83f_4167_4b4c_a1db_d2011ecb3200_str = "c708b83f-4167-4b4c-a1db-d2011ecb3200" ascii wide nocase
        $guid_c708b83f_4167_4b4c_a1db_d2011ecb3200_bin = { 3F B8 08 C7 67 41 4C 4B A1 DB D2 01 1E CB 32 00 }

        // ProxyLogon exploitation
        // https://github.com/hausec/ProxyLogon
        $guid_C715155F_2BE8_44E0_BD34_2960067874C8_str = "C715155F-2BE8-44E0-BD34-2960067874C8" ascii wide nocase
        $guid_C715155F_2BE8_44E0_BD34_2960067874C8_bin = { 5F 15 15 C7 E8 2B E0 44 BD 34 29 60 06 78 74 C8 }

        // Another Windows Local Privilege Escalation from Service Account to System
        // https://github.com/antonioCoco/JuicyPotatoNG
        $guid_C73A4893_A5D1_44C8_900C_7B8850BBD2EC_str = "C73A4893-A5D1-44C8-900C-7B8850BBD2EC" ascii wide nocase
        $guid_C73A4893_A5D1_44C8_900C_7B8850BBD2EC_bin = { 93 48 3A C7 D1 A5 C8 44 90 0C 7B 88 50 BB D2 EC }

        // Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // https://github.com/b4rtik/ATPMiniDump
        $guid_C7A0003B_98DC_4D57_8F09_5B90AAEFBDF4_str = "C7A0003B-98DC-4D57-8F09-5B90AAEFBDF4" ascii wide nocase
        $guid_C7A0003B_98DC_4D57_8F09_5B90AAEFBDF4_bin = { 3B 00 A0 C7 DC 98 57 4D 8F 09 5B 90 AA EF BD F4 }

        // Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#.
        // https://github.com/quasar/Quasar
        $guid_C7C363BA_E5B6_4E18_9224_39BC8DA73172_str = "C7C363BA-E5B6-4E18-9224-39BC8DA73172" ascii wide nocase
        $guid_C7C363BA_E5B6_4E18_9224_39BC8DA73172_bin = { BA 63 C3 C7 B6 E5 18 4E 92 24 39 BC 8D A7 31 72 }

        // extract and decrypt stored passwords from Google Chrome
        // https://github.com/BernKing/ChromeStealer
        $guid_c7c8b6fb_4e59_494e_aeeb_40cf342a7e88_str = "c7c8b6fb-4e59-494e-aeeb-40cf342a7e88" ascii wide nocase
        $guid_c7c8b6fb_4e59_494e_aeeb_40cf342a7e88_bin = { FB B6 C8 C7 59 4E 4E 49 AE EB 40 CF 34 2A 7E 88 }

        // A sleep obfuscation tool is used to encrypt the content of the .text section with RC4 (using SystemFunction032). To achieve this encryption a ROP chain is employed with QueueUserAPC and NtContinue.
        // https://github.com/RtlDallas/KrakenMask
        $guid_C7E4B529_6372_449A_9184_74E74E432FE8_str = "C7E4B529-6372-449A-9184-74E74E432FE8" ascii wide nocase
        $guid_C7E4B529_6372_449A_9184_74E74E432FE8_bin = { 29 B5 E4 C7 72 63 9A 44 91 84 74 E7 4E 43 2F E8 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_C7F1F871_8045_4414_9DC3_20F8AA42B4A1_str = "C7F1F871-8045-4414-9DC3-20F8AA42B4A1" ascii wide nocase
        $guid_C7F1F871_8045_4414_9DC3_20F8AA42B4A1_bin = { 71 F8 F1 C7 45 80 14 44 9D C3 20 F8 AA 42 B4 A1 }

        // The OpenBullet web testing application.
        // https://github.com/openbullet/OpenBullet2
        $guid_C8482002_F594_4C28_9C46_960B036540A8_str = "C8482002-F594-4C28-9C46-960B036540A8" ascii wide nocase
        $guid_C8482002_F594_4C28_9C46_960B036540A8_bin = { 02 20 48 C8 94 F5 28 4C 9C 46 96 0B 03 65 40 A8 }

        // TCP port scanner. spews SYN packets asynchronously. scanning entire Internet in under 5 minutes.
        // https://github.com/robertdavidgraham/masscan
        $guid_C88D7583_254F_4BE6_A9B9_89A5BB52E679_str = "C88D7583-254F-4BE6-A9B9-89A5BB52E679" ascii wide nocase
        $guid_C88D7583_254F_4BE6_A9B9_89A5BB52E679_bin = { 83 75 8D C8 4F 25 E6 4B A9 B9 89 A5 BB 52 E6 79 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_C8C12FA3_717F_4D35_B8B3_2E7F7A124E7C_str = "C8C12FA3-717F-4D35-B8B3-2E7F7A124E7C" ascii wide nocase
        $guid_C8C12FA3_717F_4D35_B8B3_2E7F7A124E7C_bin = { A3 2F C1 C8 7F 71 35 4D B8 B3 2E 7F 7A 12 4E 7C }

        // ProxyLogon exploitation
        // https://github.com/hausec/ProxyLogon
        $guid_c8c9275b_4f46_4d48_9096_f0ec2e4ac8eb_str = "c8c9275b-4f46-4d48-9096-f0ec2e4ac8eb" ascii wide nocase
        $guid_c8c9275b_4f46_4d48_9096_f0ec2e4ac8eb_bin = { 5B 27 C9 C8 46 4F 48 4D 90 96 F0 EC 2E 4A C8 EB }

        // PowerShell Constrained Language Mode Bypass
        // https://github.com/calebstewart/bypass-clm
        $guid_C8D738E6_8C30_4715_8AE5_6A8FBFE770A7_str = "C8D738E6-8C30-4715-8AE5-6A8FBFE770A7" ascii wide nocase
        $guid_C8D738E6_8C30_4715_8AE5_6A8FBFE770A7_bin = { E6 38 D7 C8 30 8C 15 47 8A E5 6A 8F BF E7 70 A7 }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_C91C8B29_82DF_49C0_986B_81182CF84E42_str = "C91C8B29-82DF-49C0-986B-81182CF84E42" ascii wide nocase
        $guid_C91C8B29_82DF_49C0_986B_81182CF84E42_bin = { 29 8B 1C C9 DF 82 C0 49 98 6B 81 18 2C F8 4E 42 }

        // Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // https://github.com/Mayyhem/Maestro
        $guid_C9AF8FE1_CDFC_4DDD_B314_B44AD5EAD552_str = "C9AF8FE1-CDFC-4DDD-B314-B44AD5EAD552" ascii wide nocase
        $guid_C9AF8FE1_CDFC_4DDD_B314_B44AD5EAD552_bin = { E1 8F AF C9 FC CD DD 4D B3 14 B4 4A D5 EA D5 52 }

        // alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // https://github.com/OtterHacker/SetProcessInjection
        $guid_CA280845_1F10_4E65_9DE7_D9C6513BBD91_str = "CA280845-1F10-4E65-9DE7-D9C6513BBD91" ascii wide nocase
        $guid_CA280845_1F10_4E65_9DE7_D9C6513BBD91_bin = { 45 08 28 CA 10 1F 65 4E 9D E7 D9 C6 51 3B BD 91 }

        // Find vulnerabilities in AD Group Policy
        // https://github.com/Group3r/Group3r
        $guid_CAA7AB97_F83B_432C_8F9C_C5F1530F59F7_str = "CAA7AB97-F83B-432C-8F9C-C5F1530F59F7" ascii wide nocase
        $guid_CAA7AB97_F83B_432C_8F9C_C5F1530F59F7_bin = { 97 AB A7 CA 3B F8 2C 43 8F 9C C5 F1 53 0F 59 F7 }

        // Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // https://github.com/MrEmpy/Reaper
        $guid_CB561720_0175_49D9_A114_FE3489C53661_str = "CB561720-0175-49D9-A114-FE3489C53661" ascii wide nocase
        $guid_CB561720_0175_49D9_A114_FE3489C53661_bin = { 20 17 56 CB 75 01 D9 49 A1 14 FE 34 89 C5 36 61 }

        // Dump cookies directly from Chrome process memory
        // https://github.com/Meckazin/ChromeKatz
        $guid_CB790E12_603E_4C7C_9DC1_14A50819AF8C_str = "CB790E12-603E-4C7C-9DC1-14A50819AF8C" ascii wide nocase
        $guid_CB790E12_603E_4C7C_9DC1_14A50819AF8C_bin = { 12 0E 79 CB 3E 60 7C 4C 9D C1 14 A5 08 19 AF 8C }

        // walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // https://github.com/malcomvetter/Periscope
        $guid_CBAB0FE9_F4C0_49F2_90B1_7F34593F705A_str = "CBAB0FE9-F4C0-49F2-90B1-7F34593F705A" ascii wide nocase
        $guid_CBAB0FE9_F4C0_49F2_90B1_7F34593F705A_bin = { E9 0F AB CB C0 F4 F2 49 90 B1 7F 34 59 3F 70 5A }

        // Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // https://github.com/moom825/Discord-RAT-2.0
        $guid_CC12258F_AF24_4773_A8E3_45D365BCBDE9_str = "CC12258F-AF24-4773-A8E3-45D365BCBDE9" ascii wide nocase
        $guid_CC12258F_AF24_4773_A8E3_45D365BCBDE9_bin = { 8F 25 12 CC 24 AF 73 47 A8 E3 45 D3 65 BC BD E9 }

        // WinLicense key extraction via Intel PIN
        // https://github.com/charlesnathansmith/whatlicense
        $guid_CC127443_2519_4E04_8865_A6887658CDE5_str = "CC127443-2519-4E04-8865-A6887658CDE5" ascii wide nocase
        $guid_CC127443_2519_4E04_8865_A6887658CDE5_bin = { 43 74 12 CC 19 25 04 4E 88 65 A6 88 76 58 CD E5 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_CC848BD0_3B2D_4C1E_BFCF_75A9894A581D_str = "CC848BD0-3B2D-4C1E-BFCF-75A9894A581D" ascii wide nocase
        $guid_CC848BD0_3B2D_4C1E_BFCF_75A9894A581D_bin = { D0 8B 84 CC 2D 3B 1E 4C BF CF 75 A9 89 4A 58 1D }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_CD257C0A_9071_42B4_A2FF_180622DBCA96_str = "CD257C0A-9071-42B4-A2FF-180622DBCA96" ascii wide nocase
        $guid_CD257C0A_9071_42B4_A2FF_180622DBCA96_bin = { 0A 7C 25 CD 71 90 B4 42 A2 FF 18 06 22 DB CA 96 }

        // tools for Lateral Movement/Code Execution
        // https://github.com/klezVirus/CheeseTools
        $guid_CD3578F6_01B7_48C9_9140_1AFA44B3A7C0_str = "CD3578F6-01B7-48C9-9140-1AFA44B3A7C0" ascii wide nocase
        $guid_CD3578F6_01B7_48C9_9140_1AFA44B3A7C0_bin = { F6 78 35 CD B7 01 C9 48 91 40 1A FA 44 B3 A7 C0 }

        // Indirect syscalls AV bypass
        // https://github.com/Cipher7/ChaiLdr
        $guid_cd4d53a9_2db8_4408_90a0_896b2bc4c9f8_str = "cd4d53a9-2db8-4408-90a0-896b2bc4c9f8" ascii wide nocase
        $guid_cd4d53a9_2db8_4408_90a0_896b2bc4c9f8_bin = { A9 53 4D CD B8 2D 08 44 90 A0 89 6B 2B C4 C9 F8 }

        // Extracting NetNTLM without touching lsass.exe
        // https://github.com/MzHmO/NtlmThief
        $guid_CD517B47_6CA1_4AC3_BC37_D8A27F2F03A0_str = "CD517B47-6CA1-4AC3-BC37-D8A27F2F03A0" ascii wide nocase
        $guid_CD517B47_6CA1_4AC3_BC37_D8A27F2F03A0_bin = { 47 7B 51 CD A1 6C C3 4A BC 37 D8 A2 7F 2F 03 A0 }

        // A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // https://github.com/ihamburglar/fgdump
        $guid_CD8FD3D4_15FD_489C_A334_91F551B98022_str = "CD8FD3D4-15FD-489C-A334-91F551B98022" ascii wide nocase
        $guid_CD8FD3D4_15FD_489C_A334_91F551B98022_bin = { D4 D3 8F CD FD 15 9C 48 A3 34 91 F5 51 B9 80 22 }

        // COM ViewLogger - keylogger
        // https://github.com/CICADA8-Research/Spyndicapped
        $guid_cd9c66c8_8fcb_4d43_975b_a9c8d02ad090_str = "cd9c66c8-8fcb-4d43-975b-a9c8d02ad090" ascii wide nocase
        $guid_cd9c66c8_8fcb_4d43_975b_a9c8d02ad090_bin = { C8 66 9C CD CB 8F 43 4D 97 5B A9 C8 D0 2A D0 90 }

        // Tool for viewing NTDS.dit
        // https://github.com/trustedsec/DitExplorer
        $guid_CDC4F57A_A3F7_459B_87BF_6219DADF6284_str = "CDC4F57A-A3F7-459B-87BF-6219DADF6284" ascii wide nocase
        $guid_CDC4F57A_A3F7_459B_87BF_6219DADF6284_bin = { 7A F5 C4 CD F7 A3 9B 45 87 BF 62 19 DA DF 62 84 }

        // A Silent (Hidden) Free Crypto Miner Builder
        // https://github.com/UnamSanctam/SilentCryptoMiner
        $guid_CE2307EB_A69E_0EB9_386C_D322223A10A9_str = "CE2307EB-A69E-0EB9-386C-D322223A10A9" ascii wide nocase
        $guid_CE2307EB_A69E_0EB9_386C_D322223A10A9_bin = { EB 07 23 CE 9E A6 B9 0E 38 6C D3 22 22 3A 10 A9 }

        // install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // https://github.com/trustedsec/The_Shelf
        $guid_CE23F388_34F5_4543_81D1_91CD244C9CB1_str = "CE23F388-34F5-4543-81D1-91CD244C9CB1" ascii wide nocase
        $guid_CE23F388_34F5_4543_81D1_91CD244C9CB1_bin = { 88 F3 23 CE F5 34 43 45 81 D1 91 CD 24 4C 9C B1 }

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_CE5AD78C_DBDF_4D81_9A69_41B1DF683115_str = "CE5AD78C-DBDF-4D81-9A69-41B1DF683115" ascii wide nocase
        $guid_CE5AD78C_DBDF_4D81_9A69_41B1DF683115_bin = { 8C D7 5A CE DF DB 81 4D 9A 69 41 B1 DF 68 31 15 }

        // .NET HttpClient proxy handler implementation for SOCKS proxies
        // https://github.com/bbepis/Nsocks
        $guid_CE5C7EF9_E890_48E5_8551_3E8F96DCB38F_str = "CE5C7EF9-E890-48E5-8551-3E8F96DCB38F" ascii wide nocase
        $guid_CE5C7EF9_E890_48E5_8551_3E8F96DCB38F_bin = { F9 7E 5C CE 90 E8 E5 48 85 51 3E 8F 96 DC B3 8F }

        // tool for inspecting system DLLs loaded into processes - looking for functions hooked from AV/EDR.
        // https://github.com/UmaRex01/HookSentry
        $guid_ce613fc8_3f97_4989_bc90_2027463ea37d_str = "ce613fc8-3f97-4989-bc90-2027463ea37d" ascii wide nocase
        $guid_ce613fc8_3f97_4989_bc90_2027463ea37d_bin = { C8 3F 61 CE 97 3F 89 49 BC 90 20 27 46 3E A3 7D }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_CE61ADEE_C032_43EC_ACD8_E4A742F894A3_str = "CE61ADEE-C032-43EC-ACD8-E4A742F894A3" ascii wide nocase
        $guid_CE61ADEE_C032_43EC_ACD8_E4A742F894A3_bin = { EE AD 61 CE 32 C0 EC 43 AC D8 E4 A7 42 F8 94 A3 }

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_CE62CBEE_DAA8_4E5E_AAAA_1F6FC291AB94_str = "CE62CBEE-DAA8-4E5E-AAAA-1F6FC291AB94" ascii wide nocase
        $guid_CE62CBEE_DAA8_4E5E_AAAA_1F6FC291AB94_bin = { EE CB 62 CE A8 DA 5E 4E AA AA 1F 6F C2 91 AB 94 }

        // Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // https://github.com/reveng007/SharpGmailC2
        $guid_CE895D82_85AA_41D9_935A_9625312D87D0_str = "CE895D82-85AA-41D9-935A-9625312D87D0" ascii wide nocase
        $guid_CE895D82_85AA_41D9_935A_9625312D87D0_bin = { 82 5D 89 CE AA 85 D9 41 93 5A 96 25 31 2D 87 D0 }

        // Creating a persistent service
        // https://github.com/uknowsec/CreateService
        $guid_cf25b9f3_849e_447f_a029_2fef5969eca3_str = "cf25b9f3-849e-447f-a029-2fef5969eca3" ascii wide nocase
        $guid_cf25b9f3_849e_447f_a029_2fef5969eca3_bin = { F3 B9 25 CF 9E 84 7F 44 A0 29 2F EF 59 69 EC A3 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_CF8C386C_46B2_4F40_BCB1_774C01E72B1C_str = "CF8C386C-46B2-4F40-BCB1-774C01E72B1C" ascii wide nocase
        $guid_CF8C386C_46B2_4F40_BCB1_774C01E72B1C_bin = { 6C 38 8C CF B2 46 40 4F BC B1 77 4C 01 E7 2B 1C }

        // decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // https://github.com/mez-0/DecryptRDCManager
        $guid_CF924967_0AEC_43B2_B891_D67B6DB9F523_str = "CF924967-0AEC-43B2-B891-D67B6DB9F523" ascii wide nocase
        $guid_CF924967_0AEC_43B2_B891_D67B6DB9F523_bin = { 67 49 92 CF EC 0A B2 43 B8 91 D6 7B 6D B9 F5 23 }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_CFE81801_C2C5_4444_BE67_64EFFEFDCD73_str = "CFE81801-C2C5-4444-BE67-64EFFEFDCD73" ascii wide nocase
        $guid_CFE81801_C2C5_4444_BE67_64EFFEFDCD73_bin = { 01 18 E8 CF C5 C2 44 44 BE 67 64 EF FE FD CD 73 }

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_D00C849B_4FA5_4E84_B9EF_B1C8C338647A_str = "D00C849B-4FA5-4E84-B9EF-B1C8C338647A" ascii wide nocase
        $guid_D00C849B_4FA5_4E84_B9EF_B1C8C338647A_bin = { 9B 84 0C D0 A5 4F 84 4E B9 EF B1 C8 C3 38 64 7A }

        // Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // https://github.com/danielbohannon/Invoke-Obfuscation
        $guid_d0a9150d_b6a4_4b17_a325_e3a24fed0aa9_str = "d0a9150d-b6a4-4b17-a325-e3a24fed0aa9" ascii wide nocase
        $guid_d0a9150d_b6a4_4b17_a325_e3a24fed0aa9_bin = { 0D 15 A9 D0 A4 B6 17 4B A3 25 E3 A2 4F ED 0A A9 }

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_D0CBA7AF_93F5_378A_BB11_2A5D9AA9C4D7_str = "D0CBA7AF-93F5-378A-BB11-2A5D9AA9C4D7" ascii wide nocase
        $guid_D0CBA7AF_93F5_378A_BB11_2A5D9AA9C4D7_bin = { AF A7 CB D0 F5 93 8A 37 BB 11 2A 5D 9A A9 C4 D7 }

        // walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // https://github.com/malcomvetter/Periscope
        $guid_D0DF8E42_3CED_4A5F_BB28_0C348B56BC79_str = "D0DF8E42-3CED-4A5F-BB28-0C348B56BC79" ascii wide nocase
        $guid_D0DF8E42_3CED_4A5F_BB28_0C348B56BC79_bin = { 42 8E DF D0 ED 3C 5F 4A BB 28 0C 34 8B 56 BC 79 }

        // C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // https://github.com/rvrsh3ll/SharpEdge
        $guid_D116BEC7_8DEF_4FCE_BF84_C8504EF4E481_str = "D116BEC7-8DEF-4FCE-BF84-C8504EF4E481" ascii wide nocase
        $guid_D116BEC7_8DEF_4FCE_BF84_C8504EF4E481_bin = { C7 BE 16 D1 EF 8D CE 4F BF 84 C8 50 4E F4 E4 81 }

        // A quick scanner for the CVE-2019-0708 "BlueKeep" vulnerability
        // https://github.com/robertdavidgraham/rdpscan
        $guid_D116CC32_BC4F_4FAD_B09C_0D6459D1C1B6_str = "D116CC32-BC4F-4FAD-B09C-0D6459D1C1B6" ascii wide nocase
        $guid_D116CC32_BC4F_4FAD_B09C_0D6459D1C1B6_bin = { 32 CC 16 D1 4F BC AD 4F B0 9C 0D 64 59 D1 C1 B6 }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_D19BD978_267A_4BF0_85CC_851E280FF4C2_str = "D19BD978-267A-4BF0-85CC-851E280FF4C2" ascii wide nocase
        $guid_D19BD978_267A_4BF0_85CC_851E280FF4C2_bin = { 78 D9 9B D1 7A 26 F0 4B 85 CC 85 1E 28 0F F4 C2 }

        // ADCollector is a lightweight tool that enumerates the Active Directory environment
        // https://github.com/dev-2null/ADCollector
        $guid_D1AE1ACF_8AA2_4935_ACDF_EC22BAE2DF76_str = "D1AE1ACF-8AA2-4935-ACDF-EC22BAE2DF76" ascii wide nocase
        $guid_D1AE1ACF_8AA2_4935_ACDF_EC22BAE2DF76_bin = { CF 1A AE D1 A2 8A 35 49 AC DF EC 22 BA E2 DF 76 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_D1CCDA5D_E460_4ACC_B51A_730DE8F0ECF3_str = "D1CCDA5D-E460-4ACC-B51A-730DE8F0ECF3" ascii wide nocase
        $guid_D1CCDA5D_E460_4ACC_B51A_730DE8F0ECF3_bin = { 5D DA CC D1 60 E4 CC 4A B5 1A 73 0D E8 F0 EC F3 }

        // Tool for viewing NTDS.dit
        // https://github.com/trustedsec/DitExplorer
        $guid_D1D4BB1C_798D_47B0_8525_061D40CB9E44_str = "D1D4BB1C-798D-47B0-8525-061D40CB9E44" ascii wide nocase
        $guid_D1D4BB1C_798D_47B0_8525_061D40CB9E44_bin = { 1C BB D4 D1 8D 79 B0 47 85 25 06 1D 40 CB 9E 44 }

        // indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // https://github.com/CaptainNox/Hypnos
        $guid_D210570B_F1A0_4B66_9301_F7A54978C178_str = "D210570B-F1A0-4B66-9301-F7A54978C178" ascii wide nocase
        $guid_D210570B_F1A0_4B66_9301_F7A54978C178_bin = { 0B 57 10 D2 A0 F1 66 4B 93 01 F7 A5 49 78 C1 78 }

        // audit the security of read-only domain controllers
        // https://github.com/wh0amitz/SharpRODC
        $guid_D305F8A3_019A_4CDF_909C_069D5B483613_str = "D305F8A3-019A-4CDF-909C-069D5B483613" ascii wide nocase
        $guid_D305F8A3_019A_4CDF_909C_069D5B483613_bin = { A3 F8 05 D3 9A 01 DF 4C 90 9C 06 9D 5B 48 36 13 }

        // PrintNightmare exploitation
        // https://github.com/outflanknl/PrintNightmare
        $guid_D30C9D6B_1F45_47BD_825B_389FE8CC9069_str = "D30C9D6B-1F45-47BD-825B-389FE8CC9069" ascii wide nocase
        $guid_D30C9D6B_1F45_47BD_825B_389FE8CC9069_bin = { 6B 9D 0C D3 45 1F BD 47 82 5B 38 9F E8 CC 90 69 }

        // Fake Windows logon screen to steal passwords
        // https://github.com/bitsadmin/fakelogonscreen
        $guid_D35A55BD_3189_498B_B72F_DC798172E505_str = "D35A55BD-3189-498B-B72F-DC798172E505" ascii wide nocase
        $guid_D35A55BD_3189_498B_B72F_DC798172E505_bin = { BD 55 5A D3 89 31 8B 49 B7 2F DC 79 81 72 E5 05 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_D3E7005E_6C5B_47F3_A0B3_028C81C0C1ED_str = "D3E7005E-6C5B-47F3-A0B3-028C81C0C1ED" ascii wide nocase
        $guid_D3E7005E_6C5B_47F3_A0B3_028C81C0C1ED_bin = { 5E 00 E7 D3 5B 6C F3 47 A0 B3 02 8C 81 C0 C1 ED }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_D47C706B_152F_46B5_840A_4EBB2CFAFE33_str = "D47C706B-152F-46B5-840A-4EBB2CFAFE33" ascii wide nocase
        $guid_D47C706B_152F_46B5_840A_4EBB2CFAFE33_bin = { 6B 70 7C D4 2F 15 B5 46 84 0A 4E BB 2C FA FE 33 }

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_d494a4bc_3867_436a_93ef_737f9e0522eb_str = "d494a4bc-3867-436a-93ef-737f9e0522eb" ascii wide nocase
        $guid_d494a4bc_3867_436a_93ef_737f9e0522eb_bin = { BC A4 94 D4 67 38 6A 43 93 EF 73 7F 9E 05 22 EB }

        // Process injection technique
        // https://github.com/CICADA8-Research/IHxExec
        $guid_d5092358_f3ab_4712_9c7f_d9ec4390193c_str = "d5092358-f3ab-4712-9c7f-d9ec4390193c" ascii wide nocase
        $guid_d5092358_f3ab_4712_9c7f_d9ec4390193c_bin = { 58 23 09 D5 AB F3 12 47 9C 7F D9 EC 43 90 19 3C }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_D52AB3F8_15D3_49C5_9EAC_468CDF65FB22_str = "D52AB3F8-15D3-49C5-9EAC-468CDF65FB22" ascii wide nocase
        $guid_D52AB3F8_15D3_49C5_9EAC_468CDF65FB22_bin = { F8 B3 2A D5 D3 15 C5 49 9E AC 46 8C DF 65 FB 22 }

        // Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers.
        // https://github.com/BC-SECURITY/Empire
        $guid_D5865774_CD82_4CCE_A3F1_7F2C4639301B_str = "D5865774-CD82-4CCE-A3F1-7F2C4639301B" ascii wide nocase
        $guid_D5865774_CD82_4CCE_A3F1_7F2C4639301B_bin = { 74 57 86 D5 82 CD CE 4C A3 F1 7F 2C 46 39 30 1B }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_D5C4F5A2_5713_4A0A_A833_F9466AE5A339_str = "D5C4F5A2-5713-4A0A-A833-F9466AE5A339" ascii wide nocase
        $guid_D5C4F5A2_5713_4A0A_A833_F9466AE5A339_bin = { A2 F5 C4 D5 13 57 0A 4A A8 33 F9 46 6A E5 A3 39 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_D640C36B_2C66_449B_A145_EB98322A67C8_str = "D640C36B-2C66-449B-A145-EB98322A67C8" ascii wide nocase
        $guid_D640C36B_2C66_449B_A145_EB98322A67C8_bin = { 6B C3 40 D6 66 2C 9B 44 A1 45 EB 98 32 2A 67 C8 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_D64E40BB_9DAC_4491_8406_2CA2F2853F76_str = "D64E40BB-9DAC-4491-8406-2CA2F2853F76" ascii wide nocase
        $guid_D64E40BB_9DAC_4491_8406_2CA2F2853F76_bin = { BB 40 4E D6 AC 9D 91 44 84 06 2C A2 F2 85 3F 76 }

        // Spoofing desktop login applications with WinForms and WPF
        // https://github.com/mlcsec/FormThief
        $guid_D6948EFC_AA15_413D_8EF1_032C149D3FBB_str = "D6948EFC-AA15-413D-8EF1-032C149D3FBB" ascii wide nocase
        $guid_D6948EFC_AA15_413D_8EF1_032C149D3FBB_bin = { FC 8E 94 D6 15 AA 3D 41 8E F1 03 2C 14 9D 3F BB }

        // Enumerate and decrypt TeamViewer credentials from Windows registry
        // https://github.com/V1V1/DecryptTeamViewer
        $guid_D6AAED62_BBFC_4F2A_A2A4_35EC5B2A4E07_str = "D6AAED62-BBFC-4F2A-A2A4-35EC5B2A4E07" ascii wide nocase
        $guid_D6AAED62_BBFC_4F2A_A2A4_35EC5B2A4E07_bin = { 62 ED AA D6 FC BB 2A 4F A2 A4 35 EC 5B 2A 4E 07 }

        // EfiGuard is a portable x64 UEFI bootkit that patches the Windows boot manager - boot loader and kernel at boot time in order to disable PatchGuard and Driver Signature Enforcement (DSE).
        // https://github.com/Mattiwatti/EfiGuard
        $guid_D7484EBA_6357_4D81_B355_066E28D5DF72_str = "D7484EBA-6357-4D81-B355-066E28D5DF72" ascii wide nocase
        $guid_D7484EBA_6357_4D81_B355_066E28D5DF72_bin = { BA 4E 48 D7 57 63 81 4D B3 55 06 6E 28 D5 DF 72 }

        // PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // https://github.com/topotam/PetitPotam
        $guid_D78924E1_7F2B_4315_A2D2_24124C7828F8_str = "D78924E1-7F2B-4315-A2D2-24124C7828F8" ascii wide nocase
        $guid_D78924E1_7F2B_4315_A2D2_24124C7828F8_bin = { E1 24 89 D7 2B 7F 15 43 A2 D2 24 12 4C 78 28 F8 }

        // HTTP/S Beaconing Implant
        // https://github.com/silentbreaksec/Throwback
        $guid_D7D20588_8C18_4796_B2A4_386AECF14256_str = "D7D20588-8C18-4796-B2A4-386AECF14256" ascii wide nocase
        $guid_D7D20588_8C18_4796_B2A4_386AECF14256_bin = { 88 05 D2 D7 18 8C 96 47 B2 A4 38 6A EC F1 42 56 }

        // Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // https://github.com/gitjdm/dumper2020
        $guid_D8091ED0_5E78_4AF5_93EE_A5AA6E978430_str = "D8091ED0-5E78-4AF5-93EE-A5AA6E978430" ascii wide nocase
        $guid_D8091ED0_5E78_4AF5_93EE_A5AA6E978430_bin = { D0 1E 09 D8 78 5E F5 4A 93 EE A5 AA 6E 97 84 30 }

        // erase specified records from Windows event logs
        // https://github.com/QAX-A-Team/EventCleaner
        $guid_D8A76296_A666_46C7_9CA0_254BA97E3B7C_str = "D8A76296-A666-46C7-9CA0-254BA97E3B7C" ascii wide nocase
        $guid_D8A76296_A666_46C7_9CA0_254BA97E3B7C_bin = { 96 62 A7 D8 66 A6 C7 46 9C A0 25 4B A9 7E 3B 7C }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_D8B2F4F4_2B59_4457_B710_F15844570997_str = "D8B2F4F4-2B59-4457-B710-F15844570997" ascii wide nocase
        $guid_D8B2F4F4_2B59_4457_B710_F15844570997_bin = { F4 F4 B2 D8 59 2B 57 44 B7 10 F1 58 44 57 09 97 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_D8BDABF6_6A96_4B48_8C1C_B6E78CBBF50E_str = "D8BDABF6-6A96-4B48-8C1C-B6E78CBBF50E" ascii wide nocase
        $guid_D8BDABF6_6A96_4B48_8C1C_B6E78CBBF50E_bin = { F6 AB BD D8 96 6A 48 4B 8C 1C B6 E7 8C BB F5 0E }

        // Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // https://github.com/ricardojoserf/TrickDump
        $guid_D8FC3807_CEAA_4F6A_9C8F_CC96F99D1F04_str = "D8FC3807-CEAA-4F6A-9C8F-CC96F99D1F04" ascii wide nocase
        $guid_D8FC3807_CEAA_4F6A_9C8F_CC96F99D1F04_bin = { 07 38 FC D8 AA CE 6A 4F 9C 8F CC 96 F9 9D 1F 04 }

        // C# AV/EDR Killer using less-known driver (BYOVD)
        // https://github.com/ph4nt0mbyt3/Darkside
        $guid_D90EFC93_2F8B_4427_B967_0E78ED45611E_str = "D90EFC93-2F8B-4427-B967-0E78ED45611E" ascii wide nocase
        $guid_D90EFC93_2F8B_4427_B967_0E78ED45611E_bin = { 93 FC 0E D9 8B 2F 27 44 B9 67 0E 78 ED 45 61 1E }

        // PEASS - Privilege Escalation Awesome Scripts SUITE
        // https://github.com/carlospolop/PEASS-ng
        $guid_D934058E_A7DB_493F_A741_AE8E3DF867F4_str = "D934058E-A7DB-493F-A741-AE8E3DF867F4" ascii wide nocase
        $guid_D934058E_A7DB_493F_A741_AE8E3DF867F4_bin = { 8E 05 34 D9 DB A7 3F 49 A7 41 AE 8E 3D F8 67 F4 }

        // meterpreter stager
        // https://github.com/SherifEldeeb/TinyMet
        $guid_DA06A931_7DCA_4149_853D_641B8FAA1AB9_str = "DA06A931-7DCA-4149-853D-641B8FAA1AB9" ascii wide nocase
        $guid_DA06A931_7DCA_4149_853D_641B8FAA1AB9_bin = { 31 A9 06 DA CA 7D 49 41 85 3D 64 1B 8F AA 1A B9 }

        // PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // https://github.com/GDSSecurity/PSAttack
        $guid_DA1B7904_0DDC_45A0_875F_33BBA2236C44_str = "DA1B7904-0DDC-45A0-875F-33BBA2236C44" ascii wide nocase
        $guid_DA1B7904_0DDC_45A0_875F_33BBA2236C44_bin = { 04 79 1B DA DC 0D A0 45 87 5F 33 BB A2 23 6C 44 }

        // unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $guid_DA230B64_14EA_4D49_96E1_FA5EFED9010B_str = "DA230B64-14EA-4D49-96E1-FA5EFED9010B" ascii wide nocase
        $guid_DA230B64_14EA_4D49_96E1_FA5EFED9010B_bin = { 64 0B 23 DA EA 14 49 4D 96 E1 FA 5E FE D9 01 0B }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_DA7DF89C_447D_4C2D_9C75_933037BF245E_str = "DA7DF89C-447D-4C2D-9C75-933037BF245E" ascii wide nocase
        $guid_DA7DF89C_447D_4C2D_9C75_933037BF245E_bin = { 9C F8 7D DA 7D 44 2D 4C 9C 75 93 30 37 BF 24 5E }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_DAE3997B_D51B_4D9F_9F11_2EBC6FDDF57C_str = "DAE3997B-D51B-4D9F-9F11-2EBC6FDDF57C" ascii wide nocase
        $guid_DAE3997B_D51B_4D9F_9F11_2EBC6FDDF57C_bin = { 7B 99 E3 DA 1B D5 9F 4D 9F 11 2E BC 6F DD F5 7C }

        // .Net Assembly to block ETW telemetry in current process
        // https://github.com/Soledge/BlockEtw
        $guid_DAEDF7B3_8262_4892_ADC4_425DD5F85BCA_str = "DAEDF7B3-8262-4892-ADC4-425DD5F85BCA" ascii wide nocase
        $guid_DAEDF7B3_8262_4892_ADC4_425DD5F85BCA_bin = { B3 F7 ED DA 62 82 92 48 AD C4 42 5D D5 F8 5B CA }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_DAFE686A_461B_402B_BBD7_2A2F4C87C773_str = "DAFE686A-461B-402B-BBD7-2A2F4C87C773" ascii wide nocase
        $guid_DAFE686A_461B_402B_BBD7_2A2F4C87C773_bin = { 6A 68 FE DA 1B 46 2B 40 BB D7 2A 2F 4C 87 C7 73 }

        // MaLDAPtive is a framework for LDAP SearchFilter parsing - obfuscation - deobfuscation and detection.
        // https://github.com/MaLDAPtive/Invoke-Maldaptive
        $guid_db015ab1_abcd_1234_5678_133337c0ffee_str = "db015ab1-abcd-1234-5678-133337c0ffee" ascii wide nocase
        $guid_db015ab1_abcd_1234_5678_133337c0ffee_bin = { B1 5A 01 DB CD AB 34 12 56 78 13 33 37 C0 FF EE }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_DB234158_233E_4EC4_A2CE_EF02699563A2_str = "DB234158-233E-4EC4-A2CE-EF02699563A2" ascii wide nocase
        $guid_DB234158_233E_4EC4_A2CE_EF02699563A2_bin = { 58 41 23 DB 3E 23 C4 4E A2 CE EF 02 69 95 63 A2 }

        // Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // https://github.com/CCob/DRSAT
        $guid_DB62BB65_0E29_4E95_BD4E_0AA543EF74B5_str = "DB62BB65-0E29-4E95-BD4E-0AA543EF74B5" ascii wide nocase
        $guid_DB62BB65_0E29_4E95_BD4E_0AA543EF74B5_bin = { 65 BB 62 DB 29 0E 95 4E BD 4E 0A A5 43 EF 74 B5 }

        // Adaptive DLL hijacking / dynamic export forwarding
        // https://github.com/monoxgas/Koppeling
        $guid_DB8A345D_E19C_4C2A_9FDF_16BF4DD03717_str = "DB8A345D-E19C-4C2A-9FDF-16BF4DD03717" ascii wide nocase
        $guid_DB8A345D_E19C_4C2A_9FDF_16BF4DD03717_bin = { 5D 34 8A DB 9C E1 2A 4C 9F DF 16 BF 4D D0 37 17 }

        // Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // https://github.com/moom825/Discord-RAT-2.0
        $guid_DBAE6A6E_AE23_4DE9_9AB2_6A8D2CD59DEF_str = "DBAE6A6E-AE23-4DE9-9AB2-6A8D2CD59DEF" ascii wide nocase
        $guid_DBAE6A6E_AE23_4DE9_9AB2_6A8D2CD59DEF_bin = { 6E 6A AE DB 23 AE E9 4D 9A B2 6A 8D 2C D5 9D EF }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_DC199D9E_CF10_41DD_BBCD_98E71BA8679D_str = "DC199D9E-CF10-41DD-BBCD-98E71BA8679D" ascii wide nocase
        $guid_DC199D9E_CF10_41DD_BBCD_98E71BA8679D_bin = { 9E 9D 19 DC 10 CF DD 41 BB CD 98 E7 1B A8 67 9D }

        // The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // https://github.com/hackerschoice/gsocket
        $guid_dc3c1af9_ea3d_4401_9158_eb6dda735276_str = "dc3c1af9-ea3d-4401-9158-eb6dda735276" ascii wide nocase
        $guid_dc3c1af9_ea3d_4401_9158_eb6dda735276_bin = { F9 1A 3C DC 3D EA 01 44 91 58 EB 6D DA 73 52 76 }

        // C++ stealer (passwords - cookies - forms - cards - wallets) 
        // https://github.com/SecUser1/PredatorTheStealer
        $guid_DC3E0E14_6342_41C9_BECC_3653BF533CCC_str = "DC3E0E14-6342-41C9-BECC-3653BF533CCC" ascii wide nocase
        $guid_DC3E0E14_6342_41C9_BECC_3653BF533CCC_bin = { 14 0E 3E DC 42 63 C9 41 BE CC 36 53 BF 53 3C CC }

        // The Hell's Gate technique is a method employed by malware to hide its malicious behavior and avoid detection. This technique involves executing system calls directly thus bypassing the Windows API (Application Programming Interface) which is typically monitored by EDRs
        // https://github.com/am0nsec/HellsGate
        $guid_DC6187CB_D5DF_4973_84A2_F92AAE90CDA9_str = "DC6187CB-D5DF-4973-84A2-F92AAE90CDA9" ascii wide nocase
        $guid_DC6187CB_D5DF_4973_84A2_F92AAE90CDA9_bin = { CB 87 61 DC DF D5 73 49 84 A2 F9 2A AE 90 CD A9 }

        // SMBScan is a tool to enumerate file shares on an internal network.
        // https://github.com/jeffhacks/smbscan
        $guid_dc9978d7_6299_4c5a_a22d_a039cdc716ea_str = "dc9978d7-6299-4c5a-a22d-a039cdc716ea" ascii wide nocase
        $guid_dc9978d7_6299_4c5a_a22d_a039cdc716ea_bin = { D7 78 99 DC 99 62 5A 4C A2 2D A0 39 CD C7 16 EA }

        // Command and Control Framework written in C#
        // https://github.com/rasta-mouse/SharpC2
        $guid_DE7B9E6B_F73B_4573_A4C7_D314B528CFCB_str = "DE7B9E6B-F73B-4573-A4C7-D314B528CFCB" ascii wide nocase
        $guid_DE7B9E6B_F73B_4573_A4C7_D314B528CFCB_bin = { 6B 9E 7B DE 3B F7 73 45 A4 C7 D3 14 B5 28 CF CB }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_DEED6795_9EC9_4B2C_95E0_9E465DA61755_str = "DEED6795-9EC9-4B2C-95E0-9E465DA61755" ascii wide nocase
        $guid_DEED6795_9EC9_4B2C_95E0_9E465DA61755_bin = { 95 67 ED DE C9 9E 2C 4B 95 E0 9E 46 5D A6 17 55 }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_DFE11C77_62FA_4011_8398_38626C02E382_str = "DFE11C77-62FA-4011-8398-38626C02E382" ascii wide nocase
        $guid_DFE11C77_62FA_4011_8398_38626C02E382_bin = { 77 1C E1 DF FA 62 11 40 83 98 38 62 6C 02 E3 82 }

        // Dump various types of Windows credentials without injecting in any process
        // https://github.com/quarkslab/quarkspwdump
        $guid_E0362605_CC11_4CD5_AFF7_B50934438658_str = "E0362605-CC11-4CD5-AFF7-B50934438658" ascii wide nocase
        $guid_E0362605_CC11_4CD5_AFF7_B50934438658_bin = { 05 26 36 E0 11 CC D5 4C AF F7 B5 09 34 43 86 58 }

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_E049487C_C5BD_471E_99AE_C756E70B6520_str = "E049487C-C5BD-471E-99AE-C756E70B6520" ascii wide nocase
        $guid_E049487C_C5BD_471E_99AE_C756E70B6520_bin = { 7C 48 49 E0 BD C5 1E 47 99 AE C7 56 E7 0B 65 20 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_E0695F0F_0FAF_44BC_AE55_A1FCBFE70271_str = "E0695F0F-0FAF-44BC-AE55-A1FCBFE70271" ascii wide nocase
        $guid_E0695F0F_0FAF_44BC_AE55_A1FCBFE70271_bin = { 0F 5F 69 E0 AF 0F BC 44 AE 55 A1 FC BF E7 02 71 }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_E08BAA9C_9D20_4C9A_8933_EC567F39F54C_str = "E08BAA9C-9D20-4C9A-8933-EC567F39F54C" ascii wide nocase
        $guid_E08BAA9C_9D20_4C9A_8933_EC567F39F54C_bin = { 9C AA 8B E0 20 9D 9A 4C 89 33 EC 56 7F 39 F5 4C }

        // Patching AmsiOpenSession by forcing an error branching
        // https://github.com/TheD1rkMtr/AMSI_patch
        $guid_E09F4899_D8B3_4282_9E3A_B20EE9A3D463_str = "E09F4899-D8B3-4282-9E3A-B20EE9A3D463" ascii wide nocase
        $guid_E09F4899_D8B3_4282_9E3A_B20EE9A3D463_bin = { 99 48 9F E0 B3 D8 82 42 9E 3A B2 0E E9 A3 D4 63 }

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_e11cbe43_b8bc_4042_a4a5_c8e960925c83_str = "e11cbe43-b8bc-4042-a4a5-c8e960925c83" ascii wide nocase
        $guid_e11cbe43_b8bc_4042_a4a5_c8e960925c83_bin = { 43 BE 1C E1 BC B8 42 40 A4 A5 C8 E9 60 92 5C 83 }

        // PoC Implementation of a fully dynamic call stack spoofer
        // https://github.com/klezVirus/SilentMoonwalk
        $guid_E11DC25D_E96D_495D_8968_1BA09C95B673_str = "E11DC25D-E96D-495D-8968-1BA09C95B673" ascii wide nocase
        $guid_E11DC25D_E96D_495D_8968_1BA09C95B673_bin = { 5D C2 1D E1 6D E9 5D 49 89 68 1B A0 9C 95 B6 73 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_E17B7339_C788_4DBE_B382_3AEDB024073D_str = "E17B7339-C788-4DBE-B382-3AEDB024073D" ascii wide nocase
        $guid_E17B7339_C788_4DBE_B382_3AEDB024073D_bin = { 39 73 7B E1 88 C7 BE 4D B3 82 3A ED B0 24 07 3D }

        // disable TamperProtection and other Defender / MDE components
        // https://github.com/AlteredSecurity/Disable-TamperProtection
        $guid_E192C3DF_AE34_4E32_96BA_3D6B56EA76A4_str = "E192C3DF-AE34-4E32-96BA-3D6B56EA76A4" ascii wide nocase
        $guid_E192C3DF_AE34_4E32_96BA_3D6B56EA76A4_bin = { DF C3 92 E1 34 AE 32 4E 96 BA 3D 6B 56 EA 76 A4 }

        // ScriptSentry finds misconfigured and dangerous logon scripts.
        // https://github.com/techspence/ScriptSentry
        $guid_e1cd2b55_3b4f_41bd_a168_40db41e34349_str = "e1cd2b55-3b4f-41bd-a168-40db41e34349" ascii wide nocase
        $guid_e1cd2b55_3b4f_41bd_a168_40db41e34349_bin = { 55 2B CD E1 4F 3B BD 41 A1 68 40 DB 41 E3 43 49 }

        // A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // https://github.com/ihamburglar/fgdump
        $guid_E1D50AB4_E1CD_4C31_AED5_E957D2E6B01F_str = "E1D50AB4-E1CD-4C31-AED5-E957D2E6B01F" ascii wide nocase
        $guid_E1D50AB4_E1CD_4C31_AED5_E957D2E6B01F_bin = { B4 0A D5 E1 CD E1 31 4C AE D5 E9 57 D2 E6 B0 1F }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_E211C5CD_85F0_48D2_A18F_2E59AD47DDC3_str = "E211C5CD-85F0-48D2-A18F-2E59AD47DDC3" ascii wide nocase
        $guid_E211C5CD_85F0_48D2_A18F_2E59AD47DDC3_bin = { CD C5 11 E2 F0 85 D2 48 A1 8F 2E 59 AD 47 DD C3 }

        // Tool for viewing NTDS.dit
        // https://github.com/trustedsec/DitExplorer
        $guid_E2596512_8A36_4D48_8AA1_9791E48A16CC_str = "E2596512-8A36-4D48-8AA1-9791E48A16CC" ascii wide nocase
        $guid_E2596512_8A36_4D48_8AA1_9791E48A16CC_bin = { 12 65 59 E2 36 8A 48 4D 8A A1 97 91 E4 8A 16 CC }

        // Lifetime AMSI bypass
        // https://github.com/ZeroMemoryEx/Amsi-Killer
        $guid_E2E64E89_8ACE_4AA1_9340_8E987F5F142F_str = "E2E64E89-8ACE-4AA1-9340-8E987F5F142F" ascii wide nocase
        $guid_E2E64E89_8ACE_4AA1_9340_8E987F5F142F_bin = { 89 4E E6 E2 CE 8A A1 4A 93 40 8E 98 7F 5F 14 2F }

        // .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // https://github.com/G0ldenGunSec/SharpSecDump
        $guid_E2FDD6CC_9886_456C_9021_EE2C47CF67B7_str = "E2FDD6CC-9886-456C-9021-EE2C47CF67B7" ascii wide nocase
        $guid_E2FDD6CC_9886_456C_9021_EE2C47CF67B7_bin = { CC D6 FD E2 86 98 6C 45 90 21 EE 2C 47 CF 67 B7 }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_E3104B33_DB3D_4C83_B393_1E05E1FF2B10_str = "E3104B33-DB3D-4C83-B393-1E05E1FF2B10" ascii wide nocase
        $guid_E3104B33_DB3D_4C83_B393_1E05E1FF2B10_bin = { 33 4B 10 E3 3D DB 83 4C B3 93 1E 05 E1 FF 2B 10 }

        // MeshCentral is a full computer management web site - abused by attackers
        // https://github.com/Ylianst/MeshAgent
        $guid_E377F156_BAED_4086_B534_3CC43164607A_str = "E377F156-BAED-4086-B534-3CC43164607A" ascii wide nocase
        $guid_E377F156_BAED_4086_B534_3CC43164607A_bin = { 56 F1 77 E3 ED BA 86 40 B5 34 3C C4 31 64 60 7A }

        // Bypass Credential Guard by patching WDigest.dll using only NTAPI functions
        // https://github.com/ricardojoserf/NativeBypassCredGuard
        $guid_E383DFEA_EC22_4667_9434_3F2591A03740_str = "E383DFEA-EC22-4667-9434-3F2591A03740" ascii wide nocase
        $guid_E383DFEA_EC22_4667_9434_3F2591A03740_bin = { EA DF 83 E3 22 EC 67 46 94 34 3F 25 91 A0 37 40 }

        // another C2 framework
        // https://github.com/trustedsec/The_Shelf
        $guid_E3AEA3F6_D548_4989_9A42_80BAC9321AE0_str = "E3AEA3F6-D548-4989-9A42-80BAC9321AE0" ascii wide nocase
        $guid_E3AEA3F6_D548_4989_9A42_80BAC9321AE0_bin = { F6 A3 AE E3 48 D5 89 49 9A 42 80 BA C9 32 1A E0 }

        // C# implementation of harmj0y's PowerView
        // https://github.com/tevora-threat/SharpView/
        $guid_e42e5cf9_be25_4011_9623_8565b193a506_str = "e42e5cf9-be25-4011-9623-8565b193a506" ascii wide nocase
        $guid_e42e5cf9_be25_4011_9623_8565b193a506_bin = { F9 5C 2E E4 25 BE 11 40 96 23 85 65 B1 93 A5 06 }

        // SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // https://github.com/Mayyhem/SharpSCCM/
        $guid_E4D9EF39_0FCE_4573_978B_ABF8DF6AEC23_str = "E4D9EF39-0FCE-4573-978B-ABF8DF6AEC23" ascii wide nocase
        $guid_E4D9EF39_0FCE_4573_978B_ABF8DF6AEC23_bin = { 39 EF D9 E4 CE 0F 73 45 97 8B AB F8 DF 6A EC 23 }

        // Collection of self-made Red Team tools
        // https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $guid_E51B9AEB_5F48_4C5C_837E_3A2743917427_str = "E51B9AEB-5F48-4C5C-837E-3A2743917427" ascii wide nocase
        $guid_E51B9AEB_5F48_4C5C_837E_3A2743917427_bin = { EB 9A 1B E5 48 5F 5C 4C 83 7E 3A 27 43 91 74 27 }

        // PSAmsi is a tool for auditing and defeating AMSI signatures.
        // https://github.com/cobbr/PSAmsi
        $guid_e53f158d_8aa2_8c53_da89_ab75d32c8c01_str = "e53f158d-8aa2-8c53-da89-ab75d32c8c01" ascii wide nocase
        $guid_e53f158d_8aa2_8c53_da89_ab75d32c8c01_bin = { 8D 15 3F E5 A2 8A 53 8C DA 89 AB 75 D3 2C 8C 01 }

        // perform minidump of LSASS process using few technics to avoid detection.
        // https://github.com/YOLOP0wn/POSTDump
        $guid_E54195F0_060C_4B24_98F2_AD9FB5351045_str = "E54195F0-060C-4B24-98F2-AD9FB5351045" ascii wide nocase
        $guid_E54195F0_060C_4B24_98F2_AD9FB5351045_bin = { F0 95 41 E5 0C 06 24 4B 98 F2 AD 9F B5 35 10 45 }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_E55F7214_8CC4_4E1D_AEDB_C908D23902A4_str = "E55F7214-8CC4-4E1D-AEDB-C908D23902A4" ascii wide nocase
        $guid_E55F7214_8CC4_4E1D_AEDB_C908D23902A4_bin = { 14 72 5F E5 C4 8C 1D 4E AE DB C9 08 D2 39 02 A4 }

        // Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // https://github.com/LimerBoy/Adamantium-Thief
        $guid_E6104BC9_FEA9_4EE9_B919_28156C1F2EDE_str = "E6104BC9-FEA9-4EE9-B919-28156C1F2EDE" ascii wide nocase
        $guid_E6104BC9_FEA9_4EE9_B919_28156C1F2EDE_bin = { C9 4B 10 E6 A9 FE E9 4E B9 19 28 15 6C 1F 2E DE }

        // create hidden scheduled tasks
        // https://github.com/0x727/SchTask_0x727
        $guid_E61C950E_A03D_40E2_AAD5_304C48570364_str = "E61C950E-A03D-40E2-AAD5-304C48570364" ascii wide nocase
        $guid_E61C950E_A03D_40E2_AAD5_304C48570364_bin = { 0E 95 1C E6 3D A0 E2 40 AA D5 30 4C 48 57 03 64 }

        // A tool to find folders excluded from AV real-time scanning using a time oracle
        // https://github.com/bananabr/TimeException
        $guid_e69f0324_3afb_485e_92c7_cb097ea47caf_str = "e69f0324-3afb-485e-92c7-cb097ea47caf" ascii wide nocase
        $guid_e69f0324_3afb_485e_92c7_cb097ea47caf_bin = { 24 03 9F E6 FB 3A 5E 48 92 C7 CB 09 7E A4 7C AF }

        // AoratosWin A tool that removes traces of executed applications on Windows OS
        // https://github.com/PinoyWH1Z/AoratosWin
        $guid_E731C71B_4D1B_4BE7_AA4D_EDA52AF7F256_str = "E731C71B-4D1B-4BE7-AA4D-EDA52AF7F256" ascii wide nocase
        $guid_E731C71B_4D1B_4BE7_AA4D_EDA52AF7F256_bin = { 1B C7 31 E7 1B 4D E7 4B AA 4D ED A5 2A F7 F2 56 }

        // Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // https://github.com/moom825/Discord-RAT-2.0
        $guid_E776B801_614D_4E3C_A446_5A35B0CF3D08_str = "E776B801-614D-4E3C-A446-5A35B0CF3D08" ascii wide nocase
        $guid_E776B801_614D_4E3C_A446_5A35B0CF3D08_bin = { 01 B8 76 E7 4D 61 3C 4E A4 46 5A 35 B0 CF 3D 08 }

        // a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // https://github.com/zeze-zeze/NamedPipeMaster
        $guid_E7BFFEE1_07C1_452C_8AF8_6AD30B1844FF_str = "E7BFFEE1-07C1-452C-8AF8-6AD30B1844FF" ascii wide nocase
        $guid_E7BFFEE1_07C1_452C_8AF8_6AD30B1844FF_bin = { E1 FE BF E7 C1 07 2C 45 8A F8 6A D3 0B 18 44 FF }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_E7F99164_F00F_4B2A_86A9_8EB5F659F34C_str = "E7F99164-F00F-4B2A-86A9-8EB5F659F34C" ascii wide nocase
        $guid_E7F99164_F00F_4B2A_86A9_8EB5F659F34C_bin = { 64 91 F9 E7 0F F0 2A 4B 86 A9 8E B5 F6 59 F3 4C }

        // Command line interface to dump LSASS memory to disk via SilentProcessExit
        // https://github.com/deepinstinct/LsassSilentProcessExit
        $guid_E82BCAD1_0D2B_4E95_B382_933CF78A8128_str = "E82BCAD1-0D2B-4E95-B382-933CF78A8128" ascii wide nocase
        $guid_E82BCAD1_0D2B_4E95_B382_933CF78A8128_bin = { D1 CA 2B E8 2B 0D 95 4E B3 82 93 3C F7 8A 81 28 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_E832E9B8_2158_4FC0_89A1_56C6ECC10F6B_str = "E832E9B8-2158-4FC0-89A1-56C6ECC10F6B" ascii wide nocase
        $guid_E832E9B8_2158_4FC0_89A1_56C6ECC10F6B_bin = { B8 E9 32 E8 58 21 C0 4F 89 A1 56 C6 EC C1 0F 6B }

        // Tool for viewing NTDS.dit
        // https://github.com/trustedsec/DitExplorer
        $guid_E8CA6917_CB06_4128_96CD_59676731B24A_str = "E8CA6917-CB06-4128-96CD-59676731B24A" ascii wide nocase
        $guid_E8CA6917_CB06_4128_96CD_59676731B24A_bin = { 17 69 CA E8 06 CB 28 41 96 CD 59 67 67 31 B2 4A }

        // Decrypt GlobalProtect configuration and cookie files.
        // https://github.com/rotarydrone/GlobalUnProtect
        $guid_E9172085_1595_4E98_ABF8_E890D2489BB5_str = "E9172085-1595-4E98-ABF8-E890D2489BB5" ascii wide nocase
        $guid_E9172085_1595_4E98_ABF8_E890D2489BB5_bin = { 85 20 17 E9 95 15 98 4E AB F8 E8 90 D2 48 9B B5 }

        // simple shellcode Loader - Encoders (base64 - custom - UUID - IPv4 - MAC) - Encryptors (AES) - Fileless Loader (Winhttp socket)
        // https://github.com/TheD1rkMtr/Shellcode-Hide
        $guid_E991E6A7_31EA_42E3_A471_90F0090E3AFD_str = "E991E6A7-31EA-42E3-A471-90F0090E3AFD" ascii wide nocase
        $guid_E991E6A7_31EA_42E3_A471_90F0090E3AFD_bin = { A7 E6 91 E9 EA 31 E3 42 A4 71 90 F0 09 0E 3A FD }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_E9D90B2A_F563_4A5E_9EFB_B1D6B1E7F8CB_str = "E9D90B2A-F563-4A5E-9EFB-B1D6B1E7F8CB" ascii wide nocase
        $guid_E9D90B2A_F563_4A5E_9EFB_B1D6B1E7F8CB_bin = { 2A 0B D9 E9 63 F5 5E 4A 9E FB B1 D6 B1 E7 F8 CB }

        // Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // https://github.com/Idov31/Sandman
        $guid_E9F7C24C_879D_49F2_B9BF_2477DC28E2EE_str = "E9F7C24C-879D-49F2-B9BF-2477DC28E2EE" ascii wide nocase
        $guid_E9F7C24C_879D_49F2_B9BF_2477DC28E2EE_bin = { 4C C2 F7 E9 9D 87 F2 49 B9 BF 24 77 DC 28 E2 EE }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_EA1FB2D4_B5A7_47A6_B097_2F4D29E23010_str = "EA1FB2D4-B5A7-47A6-B097-2F4D29E23010" ascii wide nocase
        $guid_EA1FB2D4_B5A7_47A6_B097_2F4D29E23010_bin = { D4 B2 1F EA A7 B5 A6 47 B0 97 2F 4D 29 E2 30 10 }

        // Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // https://github.com/GhostPack/KeeThief
        $guid_EA92F1E6_3F34_48F8_8B0A_F2BBC19220EF_str = "EA92F1E6-3F34-48F8-8B0A-F2BBC19220EF" ascii wide nocase
        $guid_EA92F1E6_3F34_48F8_8B0A_F2BBC19220EF_bin = { E6 F1 92 EA 34 3F F8 48 8B 0A F2 BB C1 92 20 EF }

        // RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // https://github.com/S12cybersecurity/RDPCredentialStealer
        $guid_ec2aaff0_b349_4855_9093_96acf6ee3299_str = "ec2aaff0-b349-4855-9093-96acf6ee3299" ascii wide nocase
        $guid_ec2aaff0_b349_4855_9093_96acf6ee3299_bin = { F0 AF 2A EC 49 B3 55 48 90 93 96 AC F6 EE 32 99 }

        // Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // https://github.com/ly4k/SpoolFool
        $guid_EC49A1B1_4DAA_47B1_90D1_787D44C641C0_str = "EC49A1B1-4DAA-47B1-90D1-787D44C641C0" ascii wide nocase
        $guid_EC49A1B1_4DAA_47B1_90D1_787D44C641C0_bin = { B1 A1 49 EC AA 4D B1 47 90 D1 78 7D 44 C6 41 C0 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_EC62CE1D_ADD7_419A_84A9_D6A04E866197_str = "EC62CE1D-ADD7-419A-84A9-D6A04E866197" ascii wide nocase
        $guid_EC62CE1D_ADD7_419A_84A9_D6A04E866197_bin = { 1D CE 62 EC D7 AD 9A 41 84 A9 D6 A0 4E 86 61 97 }

        // acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // https://github.com/decoder-it/KrbRelay-SMBServer
        $guid_ED839154_90D8_49DB_8CDD_972D1A6B2CFD_str = "ED839154-90D8-49DB-8CDD-972D1A6B2CFD" ascii wide nocase
        $guid_ED839154_90D8_49DB_8CDD_972D1A6B2CFD_bin = { 54 91 83 ED D8 90 DB 49 8C DD 97 2D 1A 6B 2C FD }

        // a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings).
        // https://github.com/Dec0ne/KrbRelayUp
        $guid_ED83E265_D48E_4B0D_8C22_D9D0A67C78F2_str = "ED83E265-D48E-4B0D-8C22-D9D0A67C78F2" ascii wide nocase
        $guid_ED83E265_D48E_4B0D_8C22_D9D0A67C78F2_bin = { 65 E2 83 ED 8E D4 0D 4B 8C 22 D9 D0 A6 7C 78 F2 }

        // .NET Post-Exploitation Utility for Abusing Explicit Certificate Mappings in ADCS
        // https://github.com/logangoins/Stifle
        $guid_EDBAAABC_1214_41C0_8EEE_B61056DE37ED_str = "EDBAAABC-1214-41C0-8EEE-B61056DE37ED" ascii wide nocase
        $guid_EDBAAABC_1214_41C0_8EEE_B61056DE37ED_bin = { BC AA BA ED 14 12 C0 41 8E EE B6 10 56 DE 37 ED }

        // leverages the Process Forking technique using the RtlCreateProcessReflection API to clone the lsass.exe process. Once the clone is created - it utilizes MINIDUMP_CALLBACK_INFORMATION callbacks to generate a memory dump of the cloned process
        // https://github.com/Offensive-Panda/LsassReflectDumping
        $guid_edd9d1b4_27f7_424a_aa21_794b19231741_str = "edd9d1b4-27f7-424a-aa21-794b19231741" ascii wide nocase
        $guid_edd9d1b4_27f7_424a_aa21_794b19231741_bin = { B4 D1 D9 ED F7 27 4A 42 AA 21 79 4B 19 23 17 41 }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_EE03FAA9_C9E8_4766_BD4E_5CD54C7F13D3_str = "EE03FAA9-C9E8-4766-BD4E-5CD54C7F13D3" ascii wide nocase
        $guid_EE03FAA9_C9E8_4766_BD4E_5CD54C7F13D3_bin = { A9 FA 03 EE E8 C9 66 47 BD 4E 5C D5 4C 7F 13 D3 }

        // notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // https://github.com/chvancooten/OSEP-Code-Snippets
        $guid_EE64B207_D973_489B_84A8_B718B93E039B_str = "EE64B207-D973-489B-84A8-B718B93E039B" ascii wide nocase
        $guid_EE64B207_D973_489B_84A8_B718B93E039B_bin = { 07 B2 64 EE 73 D9 9B 48 84 A8 B7 18 B9 3E 03 9B }

        // disable windows defender. (through the WSC api)
        // https://github.com/es3n1n/no-defender
        $guid_EE666120_EE4C_4D91_A545_66BEAA1830C1_str = "EE666120-EE4C-4D91-A545-66BEAA1830C1" ascii wide nocase
        $guid_EE666120_EE4C_4D91_A545_66BEAA1830C1_bin = { 20 61 66 EE 4C EE 91 4D A5 45 66 BE AA 18 30 C1 }

        // Decrypt Veeam database passwords
        // https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $guid_EE728741_4BD4_4F7C_8E41_B8328706EA84_str = "EE728741-4BD4-4F7C-8E41-B8328706EA84" ascii wide nocase
        $guid_EE728741_4BD4_4F7C_8E41_B8328706EA84_bin = { 41 87 72 EE D4 4B 7C 4F 8E 41 B8 32 87 06 EA 84 }

        // Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // https://github.com/TheD1rkMtr/D1rkInject
        $guid_EEC35BCF_E990_4260_828D_2B4F9AC97269_str = "EEC35BCF-E990-4260-828D-2B4F9AC97269" ascii wide nocase
        $guid_EEC35BCF_E990_4260_828D_2B4F9AC97269_bin = { CF 5B C3 EE 90 E9 60 42 82 8D 2B 4F 9A C9 72 69 }

        // Dynamically convert a native EXE to PIC shellcode by prepending a shellcode stub
        // https://github.com/senzee1984/InflativeLoading
        $guid_EEC48565_5B42_491A_8BBB_16AC0C40C367_str = "EEC48565-5B42-491A-8BBB-16AC0C40C367" ascii wide nocase
        $guid_EEC48565_5B42_491A_8BBB_16AC0C40C367_bin = { 65 85 C4 EE 42 5B 1A 49 8B BB 16 AC 0C 40 C3 67 }

        // TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // https://github.com/Flangvik/TeamFiltration
        $guid_EF143476_E53D_4C39_8DBB_A6AC7883236C_str = "EF143476-E53D-4C39-8DBB-A6AC7883236C" ascii wide nocase
        $guid_EF143476_E53D_4C39_8DBB_A6AC7883236C_bin = { 76 34 14 EF 3D E5 39 4C 8D BB A6 AC 78 83 23 6C }

        // DcRat C2 A simple remote tool in C#
        // https://github.com/qwqdanchun/DcRat
        $guid_EFFE3048_E904_48FD_B8C0_290E8E9290FB_str = "EFFE3048-E904-48FD-B8C0-290E8E9290FB" ascii wide nocase
        $guid_EFFE3048_E904_48FD_B8C0_290E8E9290FB_bin = { 48 30 FE EF 04 E9 FD 48 B8 C0 29 0E 8E 92 90 FB }

        // Fileless ring 3 rootkit with installer and persistence that hides processes, files, network connections
        // https://github.com/bytecode77/r77-rootkit
        $guid_F0005D08_6278_4BFE_B492_F86CCEC797D5_str = "F0005D08-6278-4BFE-B492-F86CCEC797D5" ascii wide nocase
        $guid_F0005D08_6278_4BFE_B492_F86CCEC797D5_bin = { 08 5D 00 F0 78 62 FE 4B B4 92 F8 6C CE C7 97 D5 }

        // Dump the memory of any PPL with a Userland exploit chain
        // https://github.com/itm4n/PPLmedic
        $guid_F00A3B5F_D9A9_4582_BBCE_FD10EFBF0C17_str = "F00A3B5F-D9A9-4582-BBCE-FD10EFBF0C17" ascii wide nocase
        $guid_F00A3B5F_D9A9_4582_BBCE_FD10EFBF0C17_bin = { 5F 3B 0A F0 A9 D9 82 45 BB CE FD 10 EF BF 0C 17 }

        // Performing Indirect Clean Syscalls
        // https://github.com/Maldev-Academy/HellHall
        $guid_F06EAC7B_6996_4E78_B045_0DF6ED201367_str = "F06EAC7B-6996-4E78-B045-0DF6ED201367" ascii wide nocase
        $guid_F06EAC7B_6996_4E78_B045_0DF6ED201367_bin = { 7B AC 6E F0 96 69 78 4E B0 45 0D F6 ED 20 13 67 }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_F0A581F1_D9BE_42EB_B262_E6A7CC839D2B_str = "F0A581F1-D9BE-42EB-B262-E6A7CC839D2B" ascii wide nocase
        $guid_F0A581F1_D9BE_42EB_B262_E6A7CC839D2B_bin = { F1 81 A5 F0 BE D9 EB 42 B2 62 E6 A7 CC 83 9D 2B }

        // NetRipper - Smart traffic sniffing for penetration testers
        // https://github.com/NytroRST/NetRipper
        $guid_F142A341_5EE0_442D_A15F_98AE9B48DBAE_str = "F142A341-5EE0-442D-A15F-98AE9B48DBAE" ascii wide nocase
        $guid_F142A341_5EE0_442D_A15F_98AE9B48DBAE_bin = { 41 A3 42 F1 E0 5E 2D 44 A1 5F 98 AE 9B 48 DB AE }

        // Credential Guard Bypass Via Patching Wdigest Memory
        // https://github.com/wh0amitz/BypassCredGuard
        $guid_F1527C49_CA1F_4994_BB9D_E20DD2C607FD_str = "F1527C49-CA1F-4994-BB9D-E20DD2C607FD" ascii wide nocase
        $guid_F1527C49_CA1F_4994_BB9D_E20DD2C607FD_bin = { 49 7C 52 F1 1F CA 94 49 BB 9D E2 0D D2 C6 07 FD }

        // This is a tool for grabbing browser passwords
        // https://github.com/QAX-A-Team/BrowserGhost
        $guid_F1653F20_D47D_4F29_8C55_3C835542AF5F_str = "F1653F20-D47D-4F29-8C55-3C835542AF5F" ascii wide nocase
        $guid_F1653F20_D47D_4F29_8C55_3C835542AF5F_bin = { 20 3F 65 F1 7D D4 29 4F 8C 55 3C 83 55 42 AF 5F }

        // Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // https://github.com/0xthirteen/SharpRDP
        $guid_F1DF1D0F_FF86_4106_97A8_F95AAF525C54_str = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" ascii wide nocase
        $guid_F1DF1D0F_FF86_4106_97A8_F95AAF525C54_bin = { 0F 1D DF F1 86 FF 06 41 97 A8 F9 5A AF 52 5C 54 }

        // Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $guid_F1E836C1_2279_49B3_84CC_ED8B048FCC44_str = "F1E836C1-2279-49B3-84CC-ED8B048FCC44" ascii wide nocase
        $guid_F1E836C1_2279_49B3_84CC_ED8B048FCC44_bin = { C1 36 E8 F1 79 22 B3 49 84 CC ED 8B 04 8F CC 44 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_F233D36D_B64A_4F14_A9F9_B8557C2D4F5D_str = "F233D36D-B64A-4F14-A9F9-B8557C2D4F5D" ascii wide nocase
        $guid_F233D36D_B64A_4F14_A9F9_B8557C2D4F5D_bin = { 6D D3 33 F2 4A B6 14 4F A9 F9 B8 55 7C 2D 4F 5D }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_F2378C48_D441_49E7_B094_1E8642A7E7C0_str = "F2378C48-D441-49E7-B094-1E8642A7E7C0" ascii wide nocase
        $guid_F2378C48_D441_49E7_B094_1E8642A7E7C0_bin = { 48 8C 37 F2 41 D4 E7 49 B0 94 1E 86 42 A7 E7 C0 }

        // credential access tool used by the Dispossessor ransomware group
        // https://github.com/n37sn4k3/BrowserDataGrabber
        $guid_f2691b74_129f_4ac2_a88a_db4b0f36b609_str = "f2691b74-129f-4ac2-a88a-db4b0f36b609" ascii wide nocase
        $guid_f2691b74_129f_4ac2_a88a_db4b0f36b609_bin = { 74 1B 69 F2 9F 12 C2 4A A8 8A DB 4B 0F 36 B6 09 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_F2D38A31_CF17_4962_A601_6779F18FDBF2_str = "F2D38A31-CF17-4962-A601-6779F18FDBF2" ascii wide nocase
        $guid_F2D38A31_CF17_4962_A601_6779F18FDBF2_bin = { 31 8A D3 F2 17 CF 62 49 A6 01 67 79 F1 8F DB F2 }

        // Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // https://github.com/WithSecureLabs/C3
        $guid_F2EC73D1_D533_4EE4_955A_A62E306472CC_str = "F2EC73D1-D533-4EE4-955A-A62E306472CC" ascii wide nocase
        $guid_F2EC73D1_D533_4EE4_955A_A62E306472CC_bin = { D1 73 EC F2 33 D5 E4 4E 95 5A A6 2E 30 64 72 CC }

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A35_str = "F3037587-1A3B-41F1-AA71-B026EFDB2A35" ascii wide nocase
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A35_bin = { 87 75 03 F3 3B 1A F1 41 AA 71 B0 26 EF DB 2A 35 }

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A40_str = "F3037587-1A3B-41F1-AA71-B026EFDB2A40" ascii wide nocase
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A40_bin = { 87 75 03 F3 3B 1A F1 41 AA 71 B0 26 EF DB 2A 40 }

        // An implementation of PSExec in C#
        // https://github.com/malcomvetter/CSExec
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A45_str = "F3037587-1A3B-41F1-AA71-B026EFDB2A45" ascii wide nocase
        $guid_F3037587_1A3B_41F1_AA71_B026EFDB2A45_bin = { 87 75 03 F3 3B 1A F1 41 AA 71 B0 26 EF DB 2A 45 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_F34C5DF4_22A6_49CF_901E_D6DD338061F1_str = "F34C5DF4-22A6-49CF-901E-D6DD338061F1" ascii wide nocase
        $guid_F34C5DF4_22A6_49CF_901E_D6DD338061F1_bin = { F4 5D 4C F3 A6 22 CF 49 90 1E D6 DD 33 80 61 F1 }

        // Github as C2
        // https://github.com/TheD1rkMtr/GithubC2
        $guid_F3C62326_E221_4481_AC57_EF7F76AAF27B_str = "F3C62326-E221-4481-AC57-EF7F76AAF27B" ascii wide nocase
        $guid_F3C62326_E221_4481_AC57_EF7F76AAF27B_bin = { 26 23 C6 F3 21 E2 81 44 AC 57 EF 7F 76 AA F2 7B }

        // The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // https://github.com/dsnezhkov/shutter
        $guid_F3FEBDE7_FBC8_48EC_8F24_5F33B8ACFB2A_str = "F3FEBDE7-FBC8-48EC-8F24-5F33B8ACFB2A" ascii wide nocase
        $guid_F3FEBDE7_FBC8_48EC_8F24_5F33B8ACFB2A_bin = { E7 BD FE F3 C8 FB EC 48 8F 24 5F 33 B8 AC FB 2A }

        // remote administration tool for Windows (RAT)
        // https://github.com/NYAN-x-CAT/Lime-RAT
        $guid_F56E4E1A_AB7A_4494_ACB9_8757164B0524_str = "F56E4E1A-AB7A-4494-ACB9-8757164B0524" ascii wide nocase
        $guid_F56E4E1A_AB7A_4494_ACB9_8757164B0524_bin = { 1A 4E 6E F5 7A AB 94 44 AC B9 87 57 16 4B 05 24 }

        // Enables users to elevate themselves to administrator-level rights
        // https://github.com/pseymour/MakeMeAdmin
        $guid_F5A53B43_5D6D_48EC_BC44_C0C1A0CEFA8D_str = "F5A53B43-5D6D-48EC-BC44-C0C1A0CEFA8D" ascii wide nocase
        $guid_F5A53B43_5D6D_48EC_BC44_C0C1A0CEFA8D_bin = { 43 3B A5 F5 6D 5D EC 48 BC 44 C0 C1 A0 CE FA 8D }

        // walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // https://github.com/malcomvetter/Periscope
        $guid_F5B94815_D623_4947_9A2B_88ABAF7FA6D9_str = "F5B94815-D623-4947-9A2B-88ABAF7FA6D9" ascii wide nocase
        $guid_F5B94815_D623_4947_9A2B_88ABAF7FA6D9_bin = { 15 48 B9 F5 23 D6 47 49 9A 2B 88 AB AF 7F A6 D9 }

        // A tool for auditing network shares in an Active Directory environment
        // https://github.com/dionach/ShareAudit
        $guid_F5BFA34B_3CDE_4C77_9162_96666303FDEA_str = "F5BFA34B-3CDE-4C77-9162-96666303FDEA" ascii wide nocase
        $guid_F5BFA34B_3CDE_4C77_9162_96666303FDEA_bin = { 4B A3 BF F5 DE 3C 77 4C 91 62 96 66 63 03 FD EA }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_F602DAFE_E8A2_4CB2_AF0E_656CD357D821_str = "F602DAFE-E8A2-4CB2-AF0E-656CD357D821" ascii wide nocase
        $guid_F602DAFE_E8A2_4CB2_AF0E_656CD357D821_bin = { FE DA 02 F6 A2 E8 B2 4C AF 0E 65 6C D3 57 D8 21 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_F60C3246_D449_412B_A858_3B5E84494D1A_str = "F60C3246-D449-412B-A858-3B5E84494D1A" ascii wide nocase
        $guid_F60C3246_D449_412B_A858_3B5E84494D1A_bin = { 46 32 0C F6 49 D4 2B 41 A8 58 3B 5E 84 49 4D 1A }

        // shadowsocks is a fast tunnel proxy that helps you bypass firewalls
        // https://github.com/shadowsocks/shadowsocks-windows
        $guid_F60CD6D5_4B1C_4293_829E_9C10D21AE8A3_str = "F60CD6D5-4B1C-4293-829E-9C10D21AE8A3" ascii wide nocase
        $guid_F60CD6D5_4B1C_4293_829E_9C10D21AE8A3_bin = { D5 D6 0C F6 1C 4B 93 42 82 9E 9C 10 D2 1A E8 A3 }

        // Xeno-RAT is an open-source remote access tool (RAT) developed in C# providing a comprehensive set of features for remote system management. Has features such as HVNC - live microphone - reverse proxy and much much more
        // https://github.com/moom825/xeno-rat
        $guid_F61EEB46_5352_4349_B880_E4A0B38EC0DB_str = "F61EEB46-5352-4349-B880-E4A0B38EC0DB" ascii wide nocase
        $guid_F61EEB46_5352_4349_B880_E4A0B38EC0DB_bin = { 46 EB 1E F6 52 53 49 43 B8 80 E4 A0 B3 8E C0 DB }

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_F70D2B71_4AAE_4B24_9DAE_55BC819C78BB_str = "F70D2B71-4AAE-4B24-9DAE-55BC819C78BB" ascii wide nocase
        $guid_F70D2B71_4AAE_4B24_9DAE_55BC819C78BB_bin = { 71 2B 0D F7 AE 4A 24 4B 9D AE 55 BC 81 9C 78 BB }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_F7581FB4_FAF5_4CD0_888A_B588F5BC69CD_str = "F7581FB4-FAF5-4CD0-888A-B588F5BC69CD" ascii wide nocase
        $guid_F7581FB4_FAF5_4CD0_888A_B588F5BC69CD_bin = { B4 1F 58 F7 F5 FA D0 4C 88 8A B5 88 F5 BC 69 CD }

        // from Malware RAT samples
        // https://github.com/x-cod3r/Remote-administration-tools-archive
        $guid_F7FA0241_1143_475B_A49A_AF44FA2F1339_str = "F7FA0241-1143-475B-A49A-AF44FA2F1339" ascii wide nocase
        $guid_F7FA0241_1143_475B_A49A_AF44FA2F1339_bin = { 41 02 FA F7 43 11 5B 47 A4 9A AF 44 FA 2F 13 39 }

        // CVE-2024-6768: Improper validation of specified quantity in input produces an unrecoverable state in CLFS.sys causing a BSoD
        // https://github.com/fortra/CVE-2024-6768
        $guid_F8285C79_AAC0_4FAD_B1DA_15CB4514B1D8_str = "F8285C79-AAC0-4FAD-B1DA-15CB4514B1D8" ascii wide nocase
        $guid_F8285C79_AAC0_4FAD_B1DA_15CB4514B1D8_bin = { 79 5C 28 F8 C0 AA AD 4F B1 DA 15 CB 45 14 B1 D8 }

        // similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // https://github.com/CICADA8-Research/RemoteKrbRelay
        $guid_F8317556_F82B_4FE2_9857_3E8DE896AA32_str = "F8317556-F82B-4FE2-9857-3E8DE896AA32" ascii wide nocase
        $guid_F8317556_F82B_4FE2_9857_3E8DE896AA32_bin = { 56 75 31 F8 2B F8 E2 4F 98 57 3E 8D E8 96 AA 32 }

        // Google Chrome Passwords , Cookies and SystemInfo Dumper
        // https://github.com/xelroth/ShadowStealer
        $guid_F835A9E7_2542_45C2_9D85_EC0C9FDFFB16_str = "F835A9E7-2542-45C2-9D85-EC0C9FDFFB16" ascii wide nocase
        $guid_F835A9E7_2542_45C2_9D85_EC0C9FDFFB16_bin = { E7 A9 35 F8 42 25 C2 45 9D 85 EC 0C 9F DF FB 16 }

        // Tools for discovery and abuse of COM hijacks
        // https://github.com/nccgroup/Accomplice
        $guid_F90C57DF_CDE4_4CDE_A2B9_9124C307D53A_str = "F90C57DF-CDE4-4CDE-A2B9-9124C307D53A" ascii wide nocase
        $guid_F90C57DF_CDE4_4CDE_A2B9_9124C307D53A_bin = { DF 57 0C F9 E4 CD DE 4C A2 B9 91 24 C3 07 D5 3A }

        // An obfuscation tool for .Net + Native files
        // https://github.com/NYAN-x-CAT/Lime-Crypter
        $guid_F93C99ED_28C9_48C5_BB90_DD98F18285A6_str = "F93C99ED-28C9-48C5-BB90-DD98F18285A6" ascii wide nocase
        $guid_F93C99ED_28C9_48C5_BB90_DD98F18285A6_bin = { ED 99 3C F9 C9 28 C5 48 BB 90 DD 98 F1 82 85 A6 }

        // Abuses the Windows containers framework to bypass EDRs.
        // https://github.com/deepinstinct/ContainYourself
        $guid_FA0DAF13_5058_4382_AE07_65E44AFB5592_str = "FA0DAF13-5058-4382-AE07-65E44AFB5592" ascii wide nocase
        $guid_FA0DAF13_5058_4382_AE07_65E44AFB5592_bin = { 13 AF 0D FA 58 50 82 43 AE 07 65 E4 4A FB 55 92 }

        // VBA payload generation framework
        // https://github.com/trustedsec/The_Shelf
        $guid_FA2052FB_9E23_43C8_A0EF_43BBB710DC61_str = "FA2052FB-9E23-43C8-A0EF-43BBB710DC61" ascii wide nocase
        $guid_FA2052FB_9E23_43C8_A0EF_43BBB710DC61_bin = { FB 52 20 FA 23 9E C8 43 A0 EF 43 BB B7 10 DC 61 }

        // Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // https://github.com/moom825/Discord-RAT-2.0
        $guid_FAA8C7E2_4409_44F5_B2CA_EBBA4D4F41F0_str = "FAA8C7E2-4409-44F5-B2CA-EBBA4D4F41F0" ascii wide nocase
        $guid_FAA8C7E2_4409_44F5_B2CA_EBBA4D4F41F0_bin = { E2 C7 A8 FA 09 44 F5 44 B2 CA EB BA 4D 4F 41 F0 }

        // Manage everything in one place
        // https://github.com/fleetdm/fleet
        $guid_FAECC814_3F3F_4CA0_8C2B_72D5E4670B92_str = "FAECC814-3F3F-4CA0-8C2B-72D5E4670B92" ascii wide nocase
        $guid_FAECC814_3F3F_4CA0_8C2B_72D5E4670B92_bin = { 14 C8 EC FA 3F 3F A0 4C 8C 2B 72 D5 E4 67 0B 92 }

        // SeTcbPrivilege exploitation
        // https://github.com/daem0nc0re/PrivFu/
        $guid_FAFE5A3C_05BC_4B6F_8BA4_2B95027CBFEA_str = "FAFE5A3C-05BC-4B6F-8BA4-2B95027CBFEA" ascii wide nocase
        $guid_FAFE5A3C_05BC_4B6F_8BA4_2B95027CBFEA_bin = { 3C 5A FE FA BC 05 6F 4B 8B A4 2B 95 02 7C BF EA }

        // Fuzzer for Windows kernel syscalls.
        // https://github.com/waleedassar/SimpleNTSyscallFuzzer
        $guid_FB351327_0816_448B_8FB7_63B550D6C808_str = "FB351327-0816-448B-8FB7-63B550D6C808" ascii wide nocase
        $guid_FB351327_0816_448B_8FB7_63B550D6C808_bin = { 27 13 35 FB 16 08 8B 44 8F B7 63 B5 50 D6 C8 08 }

        // mimikatz GUID project
        // https://github.com/gentilkiwi/mimikatz
        $guid_FB9B5E61_7C34_4280_A211_E979E1D6977F_str = "FB9B5E61-7C34-4280-A211-E979E1D6977F" ascii wide nocase
        $guid_FB9B5E61_7C34_4280_A211_E979E1D6977F_bin = { 61 5E 9B FB 34 7C 80 42 A2 11 E9 79 E1 D6 97 7F }

        // PoCs for Kernelmode rootkit techniques research.
        // https://github.com/daem0nc0re/VectorKernel/
        $guid_FC5A1C5A_65B4_452A_AA4E_E6DCF1FA04FB_str = "FC5A1C5A-65B4-452A-AA4E-E6DCF1FA04FB" ascii wide nocase
        $guid_FC5A1C5A_65B4_452A_AA4E_E6DCF1FA04FB_bin = { 5A 1C 5A FC B4 65 2A 45 AA 4E E6 DC F1 FA 04 FB }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_FC8F9DFC_3A81_4427_BFE5_DA11572EA8B5_str = "FC8F9DFC-3A81-4427-BFE5-DA11572EA8B5" ascii wide nocase
        $guid_FC8F9DFC_3A81_4427_BFE5_DA11572EA8B5_bin = { FC 9D 8F FC 81 3A 27 44 BF E5 DA 11 57 2E A8 B5 }

        // Spoof file icons and extensions in Windows
        // https://github.com/henriksb/ExtensionSpoofer
        $guid_FCD5E13D_1663_4226_8280_1C6A97933AB7_str = "FCD5E13D-1663-4226-8280-1C6A97933AB7" ascii wide nocase
        $guid_FCD5E13D_1663_4226_8280_1C6A97933AB7_bin = { 3D E1 D5 FC 63 16 26 42 82 80 1C 6A 97 93 3A B7 }

        // PoCs for sensitive token privileges such SeDebugPrivilege
        // https://github.com/daem0nc0re/PrivFu
        $guid_FCE55626_886B_4D3B_B7AA_92CECDA91514_str = "FCE55626-886B-4D3B-B7AA-92CECDA91514" ascii wide nocase
        $guid_FCE55626_886B_4D3B_B7AA_92CECDA91514_bin = { 26 56 E5 FC 6B 88 3B 4D B7 AA 92 CE CD A9 15 14 }

        // Dump the memory of a PPL with a userland exploit
        // https://github.com/itm4n/PPLdump
        $guid_FCE81BDA_ACAC_4892_969E_0414E765593B_str = "FCE81BDA-ACAC-4892-969E-0414E765593B" ascii wide nocase
        $guid_FCE81BDA_ACAC_4892_969E_0414E765593B_bin = { DA 1B E8 FC AC AC 92 48 96 9E 04 14 E7 65 59 3B }

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_FD6BDF7A_FEF4_4B28_9027_5BF750F08048_str = "FD6BDF7A-FEF4-4B28-9027-5BF750F08048" ascii wide nocase
        $guid_FD6BDF7A_FEF4_4B28_9027_5BF750F08048_bin = { 7A DF 6B FD F4 FE 28 4B 90 27 5B F7 50 F0 80 48 }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_FD93D181_2EC5_4863_8A8F_5F8C84C06B35_str = "FD93D181-2EC5-4863-8A8F-5F8C84C06B35" ascii wide nocase
        $guid_FD93D181_2EC5_4863_8A8F_5F8C84C06B35_bin = { 81 D1 93 FD C5 2E 63 48 8A 8F 5F 8C 84 C0 6B 35 }

        // collection of C# tools that include functionalities like Kerberoasting - ticket manipulation - Mimikatz - privilege escalation - domain enumeration and more
        // https://github.com/Lexus89/SharpPack
        $guid_FDD654F5_5C54_4D93_BF8E_FAF11B00E3E9_str = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" ascii wide nocase
        $guid_FDD654F5_5C54_4D93_BF8E_FAF11B00E3E9_bin = { F5 54 D6 FD 54 5C 93 4D BF 8E FA F1 1B 00 E3 E9 }

        // Dump cookies directly from Chrome process memory
        // https://github.com/Meckazin/ChromeKatz
        $guid_FDF5A0F3_73DA_4A8B_804F_EDD499A176EF_str = "FDF5A0F3-73DA-4A8B-804F-EDD499A176EF" ascii wide nocase
        $guid_FDF5A0F3_73DA_4A8B_804F_EDD499A176EF_bin = { F3 A0 F5 FD DA 73 8B 4A 80 4F ED D4 99 A1 76 EF }

        // ConfuserEx is a widely used open source obfuscator often found in malware
        // https://github.com/yck1509/ConfuserEx
        $guid_FE068381_F170_4C37_82C4_11A81FE60F1A_str = "FE068381-F170-4C37-82C4-11A81FE60F1A" ascii wide nocase
        $guid_FE068381_F170_4C37_82C4_11A81FE60F1A_bin = { 81 83 06 FE 70 F1 37 4C 82 C4 11 A8 1F E6 0F 1A }

        // Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // https://github.com/Flangvik/SharpAppLocker
        $guid_FE102D27_DEC4_42E2_BF69_86C79E08B67D_str = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" ascii wide nocase
        $guid_FE102D27_DEC4_42E2_BF69_86C79E08B67D_bin = { 27 2D 10 FE C4 DE E2 42 BF 69 86 C7 9E 08 B6 7D }

        // creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // https://github.com/rasta-mouse/RuralBishop
        $guid_FE4414D9_1D7E_4EEB_B781_D278FE7A5619_str = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii wide nocase
        $guid_FE4414D9_1D7E_4EEB_B781_D278FE7A5619_bin = { D9 14 44 FE 7E 1D EB 4E B7 81 D2 78 FE 7A 56 19 }

        // remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $guid_FE66CDDF_8E33_4153_81AF_24BE392698D8_str = "FE66CDDF-8E33-4153-81AF-24BE392698D8" ascii wide nocase
        $guid_FE66CDDF_8E33_4153_81AF_24BE392698D8_bin = { DF CD 66 FE 33 8E 53 41 81 AF 24 BE 39 26 98 D8 }

        // A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // https://github.com/hlldz/dazzleUP
        $guid_FE8F0D23_BDD1_416D_8285_F947BA86D155_str = "FE8F0D23-BDD1-416D-8285-F947BA86D155" ascii wide nocase
        $guid_FE8F0D23_BDD1_416D_8285_F947BA86D155_bin = { 23 0D 8F FE D1 BD 6D 41 82 85 F9 47 BA 86 D1 55 }

        // Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // https://github.com/gremwell/o365enum
        $guid_fea01b74_7a60_4142_a54d_7aa8f6471c00_str = "fea01b74-7a60-4142-a54d-7aa8f6471c00" ascii wide nocase
        $guid_fea01b74_7a60_4142_a54d_7aa8f6471c00_bin = { 74 1B A0 FE 60 7A 42 41 A5 4D 7A A8 F6 47 1C 00 }

        // A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // https://github.com/netero1010/ScheduleRunner
        $guid_FF5F7C4C_6915_4C53_9DA3_B8BE6C5F1DB9_str = "FF5F7C4C-6915-4C53-9DA3-B8BE6C5F1DB9" ascii wide nocase
        $guid_FF5F7C4C_6915_4C53_9DA3_B8BE6C5F1DB9_bin = { 4C 7C 5F FF 15 69 53 4C 9D A3 B8 BE 6C 5F 1D B9 }

        // EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // https://github.com/wavestone-cdt/EDRSandblast
        $guid_FFA0FDDE_BE70_49E4_97DE_753304EF1113_str = "FFA0FDDE-BE70-49E4-97DE-753304EF1113" ascii wide nocase
        $guid_FFA0FDDE_BE70_49E4_97DE_753304EF1113_bin = { DE FD A0 FF 70 BE E4 49 97 DE 75 33 04 EF 11 13 }

        // Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // https://github.com/Meltedd/HVNC
        $guid_FFE5AD77_8AF4_4A3F_8CE7_6BDC45565F07_str = "FFE5AD77-8AF4-4A3F-8CE7-6BDC45565F07" ascii wide nocase
        $guid_FFE5AD77_8AF4_4A3F_8CE7_6BDC45565F07_bin = { 77 AD E5 FF F4 8A 3F 4A 8C E7 6B DC 45 56 5F 07 }


    condition:
        any of them
}
