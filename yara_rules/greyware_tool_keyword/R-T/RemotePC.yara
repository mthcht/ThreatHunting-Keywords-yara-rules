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
        $string1 = /\s\/f\s\/im\sRemotePCS/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string2 = /\screate\sRPCService\sstart\=/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string3 = /\screate\sViewerService\sstart\=auto/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string4 = /\s\-i\sremotepc\.deb/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string5 = /\sRemotePC\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string6 = /\sRemotePCAttendedService\s/ nocase ascii wide
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
        $string13 = /\"RemotePCAttendedService\"/ nocase ascii wide
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
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string51 = /\\RemotePC\.Common\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string52 = /\\RemotePC\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string53 = /\\RemotePC\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string54 = /\\RemotePC\.lnk/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string55 = /\\RemotePC\.tmp/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string56 = /\\RemotePC\.tmp/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string57 = /\\RemotePC\\.{0,1000}\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string58 = /\\RemotePCAttended\.dmg/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string59 = /\\RemotePCCopyPaste\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string60 = /\\RemotePCDDriver\.cat/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string61 = /\\RemotePCDDriver\.inf/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string62 = /\\RemotePCDDriver\.inf/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string63 = /\\RemotePCDDriverumode1_0\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string64 = /\\RemotePCDDriverumode1_2\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string65 = /\\RemotePCDesktop\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string66 = /\\RemotePCDnD\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string67 = /\\RemotePCDnDLauncher\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string68 = /\\RemotePCHDDesktop\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string69 = /\\RemotePCHDService\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string70 = /\\remotepclauncher\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string71 = /\\RemotePCModules\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string72 = /\\RemotePCPDF\.conf/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string73 = /\\RemotePCPDF\.conf/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string74 = /\\RemotePCPerformancePlugins\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string75 = /\\RemotePCPrinter\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string76 = /\\RemotePCPrinter\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string77 = /\\RemotePCPrinter\.exe\.config/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string78 = /\\RemotePCPrinter\.pdb/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string79 = /\\RemotePCPrinterCore\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string80 = /\\RemotePCPrinterCore\.pdb/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string81 = /\\RemotePCProxys\.dat/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string82 = /\\RemotePCPS5UI\.DLL/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string83 = /\\RemotePCPS5UI\.DLL/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string84 = /\\RemotePCPSCRIPT\./ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string85 = /\\RemotePCPSCRIPT\.HLP/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string86 = /\\RemotePCPSCRIPT\.NTF/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string87 = /\\RemotePCPSCRIPT5\.DLL/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string88 = /\\RemotePCService\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string89 = /\\RemotePCService\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string90 = /\\RemotePCService_2\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string91 = /\\RemotePCSuite\.dmg/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string92 = /\\RemotePCUDE\.cat/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string93 = /\\RemotePCUDE\.inf/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string94 = /\\RemotePCUDE\.sys/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string95 = /\\RemotePCUDE\.sys/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string96 = /\\RemotePCUDEHost\.cat/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string97 = /\\RemotePCUDEHost\.inf/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string98 = /\\RemotePCUDEHost\.sys/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string99 = /\\RemotePCUIA\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string100 = /\\RemotePCUIU\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string101 = /\\remotepcuiu\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string102 = /\\RemotePCViewer\.msi/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string103 = /\\RpcAccessPermissionNotifier\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string104 = /\\RpcAccessPermissionNotifier\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string105 = /\\RpcApp\\RPCCodecEngine\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string106 = /\\RpcApp\\Tools\\Chat\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string107 = /\\RpcApp\\Tools\\Chat\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string108 = /\\RpcApp\\Tools\\TransferServer\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string109 = /\\RPCAppLauncherLogFile\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string110 = /\\RPCAttended\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string111 = /\\RPCAttendedAdmin\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string112 = /\\RPCCertificate\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string113 = /\\RPCCertificate\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string114 = /\\RPCClipboard\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string115 = /\\RPCClipboardAttended\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string116 = /\\RPCConfig\.ini/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string117 = /\\RPCCoreViewer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string118 = /\\RPCCoreViewerL\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string119 = /\\RpcDND_Console\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string120 = /\\RpcDND_Console\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string121 = /\\RPCDownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string122 = /\\rpcdownloader\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string123 = /\\RPCDownloaderLogFile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string124 = /\\RPCDownloaderLogFile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string125 = /\\RPCDragDrop\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string126 = /\\RPCFirewallAttended\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string127 = /\\RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string128 = /\\RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string129 = /\\RPCFireWallRulelogfile\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string130 = /\\RPCKeyMouseHandler\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string131 = /\\RPCOTABootstrapper\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string132 = /\\RPCOTADesktop\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string133 = /\\RPCOTADesktopUAC\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string134 = /\\RpcOTADND_Console\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string135 = /\\RPCOTAElevator\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string136 = /\\RPCOTAFTHost\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string137 = /\\RPCOTAKillService\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string138 = /\\RPCOTARelauncher\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string139 = /\\RPCOTAService\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string140 = /\\RPCOTAServiceUAC\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string141 = /\\RPCOTAUtilityHost\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string142 = /\\RPCOTAViewerHostKeyPopup\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string143 = /\\RPCPerformanceService\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string144 = /\\RPCPerformanceService\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string145 = /\\RPCPerformanceService\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string146 = /\\RPCPerfViewer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string147 = /\\rpcperfviewer\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string148 = /\\RPCPerfViewer\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string149 = /\\RPCPing\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string150 = /\\RPCPreUninstall\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string151 = /\\RPCPreUninstall\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string152 = /\\RPCPrinterDownloader\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string153 = /\\RPCPrinterDownloader\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string154 = /\\RPCPrinterDownloader\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string155 = /\\RPCProxyLatency\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string156 = /\\RPCProxyLatency\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string157 = /\\RPCProxyLatencyAttended\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string158 = /\\RPCSettings\.ini/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string159 = /\\RPCSettings\.ini/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string160 = /\\RpcStickyNotes\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string161 = /\\RPCSuite_.{0,1000}_Inc\.log/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string162 = /\\RPCsuiteLaunch\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string163 = /\\Schedule\\TaskCache\\Tree\\RemotePC/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string164 = /\\Services\\RemotePCAttendedService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string165 = /\\Tools\\Ninja\.WebSockets\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string166 = /\\Tracing\\RemotePCLauncher_/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string167 = /\\Tracing\\RemotePCUIU/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string168 = /\\TransferClient\.exe\.config/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string169 = /\\TransferServer\.exe\.config/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string170 = /\\ViewerHostKeyPopup\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string171 = /\\viewerhostkeypopup\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string172 = /\\ViewerHostKeyPopup\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string173 = /\\WOW6432Node\\RemotePC/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string174 = /AppData\\Local\\Temp\\RemotePC\sAttended/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string175 = /download\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string176 = /download\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string177 = /HKCR\\REMOTEPC/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string178 = /https\:\/\/login\.remotepc\.com\/rpcnew/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string179 = /ip\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string180 = /login\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string181 = /net\sstart\sRPCPerformanceService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string182 = /program\sfiles\s\(x86\)\\remotepc\\/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string183 = /ProgramData\\RemotePC\sPerformance/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string184 = /ProgramData\\RemotePC/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string185 = /RemotePC\s\(1\)\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string186 = /RemotePC\sPerformance\sPrinter\.url/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string187 = /RemotePC.{0,1000}\s\-\sA\snew\scomputer\shas\sbeen\sadded\sto\syour\saccount/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string188 = /RemotePC\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string189 = /RemotePC\.WebSockets\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string190 = /RemotePC\\REMOTE\~2\.DLL/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string191 = /RemotePCAttended\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string192 = /RemotePCAttendedService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string193 = /RemotePCBlackScreenApp\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string194 = /RemotePCCopyPaste\.txt/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string195 = /RemotePCDesktop\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string196 = /RemotePCDesktop\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string197 = /RemotePCDesktop\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string198 = /RemotePCHDDesktop\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string199 = /RemotePCHDService\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string200 = /remotepclauncher\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string201 = /RemotePCModules\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string202 = /RemotePCPerformanceWebLauncher\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string203 = /RemotePCPerformanceWebLauncher\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string204 = /RemotePCPrinter\.exe\.config/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string205 = /RemotePCPrinting\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string206 = /RemotePCPrintView\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string207 = /RemotePCProxys\.dat/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string208 = /RemotePCService\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string209 = /RemotePCService\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string210 = /RemotePCService_2\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string211 = /RemotePCShortcut\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string212 = /RemotePCSuite\.Model\.dll/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string213 = /RemotePCSuite\.Service\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string214 = /RemotePCSuite\.Service\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string215 = /remotepcuiu\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string216 = /RpcApp.{0,1000}TransferClient\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string217 = /RpcApp.{0,1000}TransferServer\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string218 = /RpcApp\\Tools\\TransferClient\.exe/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string219 = /RPCAttendedInstaller\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string220 = /rpcdownloader\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string221 = /RPCDownloaderLogFile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string222 = /RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string223 = /RPCFireWallRulelogfile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string224 = /RPCKeyMouseHandler\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string225 = /RPCPerformanceHealthCheck/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string226 = /rpcperformanceservice\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string227 = /RPCPerformanceService\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string228 = /rpcperfviewer\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string229 = /RPCPerfViewer\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string230 = /rpcprinterdownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string231 = /RPCProxyLatency\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string232 = /RPCsuiteLaunch\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string233 = /rule\sname\=\"TransferServer\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string234 = /sc\s\sdelete\s\"RPCService\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string235 = /sc\s\sstart\s\"RPCService\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string236 = /sc\s\sstop\s\"RPCService\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string237 = /sc\screate\sRPCService\sstart\=auto/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string238 = /sc\screate\sRPCService/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string239 = /sc\sdelete\s\"RPCService\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string240 = /sc\sdelete\sViewerService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string241 = /sc\sstart\sViewerService/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string242 = /sc\sstop\s\"RPCService\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string243 = /sc\sstop\sViewerService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string244 = /StartRPCPerformanceService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string245 = /StartRPCPerformanceServiceOnStart/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string246 = /static\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string247 = /static\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string248 = /Uninstall\sRemotePC\.lnk/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string249 = /viewerhostkeypopup\.exe\s/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string250 = /web1\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string251 = /web1\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC Remote administration tool
        // Reference: https://remotepc.com/
        $string252 = /www1\.remotepc\.com/ nocase ascii wide

    condition:
        any of them
}
