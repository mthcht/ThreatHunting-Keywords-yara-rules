rule RemotePC
{
    meta:
        description = "Detection patterns for the tool 'RemotePC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemotePC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string1 = " /f /im RemotePCS" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string2 = " create RPCService start=" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string3 = " create ViewerService start=auto" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string4 = /\s\-i\sremotepc\.deb/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string5 = /\sRemotePC\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string6 = " RemotePCAttendedService " nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string7 = /\sremotepclauncher\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string8 = /\sremotepcuiu\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string9 = /\sRemotePCViewer\.msi/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string10 = /\srpcdownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string11 = /\srpcperfviewer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string12 = /\sRPCWinXP\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string13 = "\"RemotePCAttendedService\"" nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string14 = /\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string15 = /\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string16 = /\/AttendedUDP\.zip/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string17 = /\/remotepc\.deb/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string18 = /\/remotepc\.deb/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string19 = /\/RemotePC\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string20 = /\/RemotePC\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string21 = /\/RemotePC\.lnk/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string22 = /\/RemotePC\.tmp/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string23 = /\/remotepc\-attended\.deb/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string24 = /\/RemotePCAttended\.dmg/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string25 = /\/remotepclauncher\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string26 = /\/RemotePCSuite\.dmg/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string27 = /\/remotepcuiu\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string28 = /\/RemotePCViewer\.msi/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string29 = /\/RpcDND_Console\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string30 = /\/rpcdownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string31 = /\/RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string32 = /\/rpcperfviewer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string33 = /\/RPCProxyLatency\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string34 = /\/viewerhostkeypopup\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string35 = /\\AttendedServiceRemove\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string36 = /\\AttendedUDP\.zip/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string37 = /\\BSUtility\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string38 = /\\Control\\Print\\Monitors\\REMOTEPCPRINTER/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string39 = /\\CurrentVersion\\App\sPaths\\RemotePCPerformance/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string40 = /\\CurrentVersion\\Devices\\RemotePC\sPrinter/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string41 = /\\InventoryApplicationFile\\rpcattendedadmin/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string42 = /\\Print\\Printers\\RemotePC\sPrinter\\/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string43 = /\\Program\sFiles\s\(x86\)\\RemotePC\\/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string44 = /\\program\sfiles\s\(x86\)\\remotepc\\remotepcperformance\\/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string45 = /\\ProgramData\\RemotePC/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string46 = /\\RemotePC\s\(1\)\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string47 = /\\RemotePC\sAttended\.lnk/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string48 = /\\RemotePC\sAttended\\/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string49 = /\\RemotePC\sPerformance\sHost\\/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string50 = /\\RemotePC\.Common\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string51 = /\\RemotePC\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string52 = /\\RemotePC\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string53 = /\\RemotePC\.lnk/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string54 = /\\RemotePC\.tmp/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string55 = /\\RemotePC\.tmp/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string56 = /\\RemotePC\\.{0,1000}\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string57 = /\\RemotePCAttended\.dmg/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string58 = /\\RemotePCCopyPaste\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string59 = /\\RemotePCDDriver\.cat/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string60 = /\\RemotePCDDriver\.inf/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string61 = /\\RemotePCDDriverumode1_0\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string62 = /\\RemotePCDDriverumode1_2\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string63 = /\\RemotePCDesktop\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string64 = /\\RemotePCDnD\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string65 = /\\RemotePCDnDLauncher\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string66 = /\\RemotePCHDDesktop\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string67 = /\\RemotePCHDService\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string68 = /\\remotepclauncher\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string69 = /\\RemotePCModules\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string70 = /\\RemotePCPDF\.conf/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string71 = /\\RemotePCPerformancePlugins\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string72 = /\\RemotePCPrinter\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string73 = /\\RemotePCPrinter\.exe\.config/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string74 = /\\RemotePCPrinter\.pdb/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string75 = /\\RemotePCPrinterCore\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string76 = /\\RemotePCPrinterCore\.pdb/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string77 = /\\RemotePCProxys\.dat/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string78 = /\\RemotePCPS5UI\.DLL/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string79 = /\\RemotePCPS5UI\.DLL/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string80 = /\\RemotePCPSCRIPT\./ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string81 = /\\RemotePCPSCRIPT\.HLP/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string82 = /\\RemotePCPSCRIPT\.NTF/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string83 = /\\RemotePCPSCRIPT5\.DLL/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string84 = /\\RemotePCService\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string85 = /\\RemotePCService\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string86 = /\\RemotePCService_2\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string87 = /\\RemotePCSuite\.dmg/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string88 = /\\RemotePCUDE\.cat/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string89 = /\\RemotePCUDE\.inf/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string90 = /\\RemotePCUDE\.sys/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string91 = /\\RemotePCUDEHost\.cat/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string92 = /\\RemotePCUDEHost\.inf/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string93 = /\\RemotePCUDEHost\.sys/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string94 = /\\RemotePCUIA\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string95 = /\\RemotePCUIU\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string96 = /\\remotepcuiu\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string97 = /\\RemotePCViewer\.msi/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string98 = /\\RpcAccessPermissionNotifier\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string99 = /\\RpcApp\\RPCCodecEngine\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string100 = /\\RpcApp\\Tools\\Chat\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string101 = /\\RpcApp\\Tools\\TransferServer\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string102 = /\\RPCAppLauncherLogFile\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string103 = /\\RPCAttended\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string104 = /\\RPCAttendedAdmin\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string105 = /\\RPCCertificate\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string106 = /\\RPCClipboard\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string107 = /\\RPCClipboardAttended\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string108 = /\\RPCConfig\.ini/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string109 = /\\RPCCoreViewer\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string110 = /\\RpcDND_Console\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string111 = /\\RPCDownloader\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string112 = /\\RPCDownloaderLogFile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string113 = /\\RPCDragDrop\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string114 = /\\RPCFirewallAttended\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string115 = /\\RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string116 = /\\RPCFireWallRulelogfile\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string117 = /\\RPCKeyMouseHandler\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string118 = /\\RPCOTABootstrapper\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string119 = /\\RPCOTADesktop\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string120 = /\\RPCOTADesktopUAC\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string121 = /\\RpcOTADND_Console\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string122 = /\\RPCOTAElevator\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string123 = /\\RPCOTAFTHost\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string124 = /\\RPCOTAKillService\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string125 = /\\RPCOTARelauncher\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string126 = /\\RPCOTAService\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string127 = /\\RPCOTAServiceUAC\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string128 = /\\RPCOTAUtilityHost\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string129 = /\\RPCOTAViewerHostKeyPopup\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string130 = /\\RPCPerformanceService\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string131 = /\\RPCPerformanceService\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string132 = /\\RPCPerfViewer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string133 = /\\rpcperfviewer\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string134 = /\\RPCPerfViewer\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string135 = /\\RPCPing\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string136 = /\\RPCPreUninstall\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string137 = /\\RPCPreUninstall\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string138 = /\\RPCPrinterDownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string139 = /\\RPCPrinterDownloader\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string140 = /\\RPCProxyLatency\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string141 = /\\RPCProxyLatencyAttended\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string142 = /\\RPCSettings\.ini/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string143 = /\\RpcStickyNotes\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string144 = /\\RPCSuite_.{0,1000}_Inc\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string145 = /\\RPCsuiteLaunch\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string146 = /\\Schedule\\TaskCache\\Tree\\RemotePC/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string147 = /\\Services\\RemotePCAttendedService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string148 = /\\Tools\\Ninja\.WebSockets\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string149 = /\\Tracing\\RemotePCLauncher_/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string150 = /\\Tracing\\RemotePCUIU/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string151 = /\\TransferClient\.exe\.config/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string152 = /\\TransferServer\.exe\.config/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string153 = /\\ViewerHostKeyPopup\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string154 = /\\ViewerHostKeyPopup\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string155 = /\\WOW6432Node\\RemotePC/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string156 = /AppData\\Local\\Temp\\RemotePC\sAttended/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string157 = /download\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string158 = /HKCR\\REMOTEPC/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string159 = /https\:\/\/login\.remotepc\.com\/rpcnew/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string160 = /ip\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string161 = /login\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string162 = "net start RPCPerformanceService" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string163 = /program\sfiles\s\(x86\)\\remotepc\\/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string164 = /ProgramData\\RemotePC\sPerformance/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string165 = /ProgramData\\RemotePC/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string166 = /RemotePC\s\(1\)\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string167 = /RemotePC\sPerformance\sPrinter\.url/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string168 = /RemotePC.{0,1000}\s\-\sA\snew\scomputer\shas\sbeen\sadded\sto\syour\saccount/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string169 = /RemotePC\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string170 = /RemotePC\.WebSockets\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string171 = /RemotePC\\REMOTE\~2\.DLL/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string172 = /RemotePCAttended\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string173 = "RemotePCAttendedService" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string174 = /RemotePCBlackScreenApp\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string175 = /RemotePCCopyPaste\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string176 = /RemotePCDesktop\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string177 = /RemotePCDesktop\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string178 = /RemotePCHDDesktop\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string179 = /RemotePCHDService\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string180 = /remotepclauncher\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string181 = /RemotePCModules\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string182 = /RemotePCPerformanceWebLauncher\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string183 = /RemotePCPerformanceWebLauncher\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string184 = /RemotePCPrinter\.exe\.config/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string185 = /RemotePCPrinting\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string186 = /RemotePCPrintView\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string187 = /RemotePCProxys\.dat/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string188 = /RemotePCService\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string189 = /RemotePCService\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string190 = /RemotePCService_2\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string191 = /RemotePCShortcut\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string192 = /RemotePCSuite\.Model\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string193 = /RemotePCSuite\.Service\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string194 = /remotepcuiu\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string195 = /RpcApp.{0,1000}TransferClient\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string196 = /RpcApp.{0,1000}TransferServer\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string197 = /RpcApp\\Tools\\TransferClient\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string198 = /RPCAttendedInstaller\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string199 = /rpcdownloader\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string200 = /RPCDownloaderLogFile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string201 = /RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string202 = /RPCFireWallRulelogfile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string203 = /RPCKeyMouseHandler\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string204 = "RPCPerformanceHealthCheck" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string205 = /rpcperformanceservice\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string206 = /RPCPerformanceService\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string207 = /rpcperfviewer\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string208 = /RPCPerfViewer\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string209 = /rpcprinterdownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string210 = /RPCProxyLatency\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string211 = /RPCsuiteLaunch\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string212 = "rule name=\"TransferServer\"" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string213 = "sc  delete \"RPCService\"" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string214 = "sc  start \"RPCService\"" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string215 = "sc  stop \"RPCService\"" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string216 = "sc create RPCService start=auto" nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string217 = "sc create RPCService" nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string218 = "sc delete \"RPCService\"" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string219 = "sc delete ViewerService" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string220 = "sc start ViewerService" nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string221 = "sc stop \"RPCService\"" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string222 = "sc stop ViewerService" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string223 = "StartRPCPerformanceService" nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string224 = "StartRPCPerformanceServiceOnStart" nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string225 = /static\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string226 = /Uninstall\sRemotePC\.lnk/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string227 = /viewerhostkeypopup\.exe\s/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string228 = /web1\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string229 = /www1\.remotepc\.com/ nocase ascii wide

    condition:
        any of them
}
