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
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string6 = /\sremotepclauncher\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string7 = /\sremotepcuiu\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string8 = /\srpcdownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string9 = /\srpcperfviewer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string10 = /\sRPCWinXP\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string11 = /\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string12 = /\/remotepc\.deb/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string13 = /\/RemotePC\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string14 = /\/RemotePC\.lnk/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string15 = /\/RemotePC\.tmp/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string16 = /\/remotepclauncher\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string17 = /\/remotepcuiu\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string18 = /\/RpcDND_Console\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string19 = /\/rpcdownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string20 = /\/RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string21 = /\/rpcperfviewer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string22 = /\/RPCProxyLatency\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string23 = /\/viewerhostkeypopup\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string24 = /\\Control\\Print\\Monitors\\REMOTEPCPRINTER/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string25 = /\\CurrentVersion\\App\sPaths\\RemotePCPerformance/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string26 = /\\CurrentVersion\\Devices\\RemotePC\sPrinter/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string27 = /\\Print\\Printers\\RemotePC\sPrinter\\/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string28 = /\\program\sfiles\s\(x86\)\\remotepc\\remotepcperformance\\/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string29 = /\\RemotePC\sPerformance\sHost\\/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string30 = /\\RemotePC\.Common\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string31 = /\\RemotePC\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string32 = /\\RemotePC\.lnk/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string33 = /\\RemotePC\.tmp/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string34 = /\\RemotePC\\.{0,1000}\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string35 = /\\RemotePCDDriver\.inf/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string36 = /\\remotepclauncher\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string37 = /\\RemotePCPDF\.conf/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string38 = /\\RemotePCPrinter\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string39 = /\\RemotePCPS5UI\.DLL/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string40 = /\\RemotePCPSCRIPT\./ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string41 = /\\RemotePCUDE\.sys/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string42 = /\\remotepcuiu\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string43 = /\\RpcAccessPermissionNotifier\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string44 = /\\RpcApp\\RPCCodecEngine\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string45 = /\\RpcApp\\Tools\\Chat\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string46 = /\\RPCCertificate\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string47 = /\\RPCClipboard\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string48 = /\\RPCConfig\.ini/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string49 = /\\RPCCoreViewerL\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string50 = /\\RpcDND_Console\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string51 = /\\rpcdownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string52 = /\\RPCDownloaderLogFile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string53 = /\\RPCDragDrop\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string54 = /\\RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string55 = /\\RPCPerformanceService\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string56 = /\\rpcperfviewer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string57 = /\\RPCPing\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string58 = /\\RPCPreUninstall\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string59 = /\\RPCPrinterDownloader\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string60 = /\\RPCProxyLatency\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string61 = /\\RPCSettings\.ini/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string62 = /\\RpcStickyNotes\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string63 = /\\RPCSuite_.{0,1000}_Inc\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string64 = /\\Schedule\\TaskCache\\Tree\\RemotePC/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string65 = /\\Tools\\Ninja\.WebSockets\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string66 = /\\Tracing\\RemotePCLauncher_/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string67 = /\\Tracing\\RemotePCUIU/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string68 = /\\TransferClient\.exe\.config/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string69 = /\\TransferServer\.exe\.config/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string70 = /\\viewerhostkeypopup\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string71 = /\\ViewerHostKeyPopup\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string72 = /\\WOW6432Node\\RemotePC/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string73 = /download\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string74 = /HKCR\\REMOTEPC/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string75 = /ip\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string76 = /login\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string77 = /net\sstart\sRPCPerformanceService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string78 = /program\sfiles\s\(x86\)\\remotepc\\/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string79 = /ProgramData\\RemotePC\sPerformance/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string80 = /ProgramData\\RemotePC/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string81 = /RemotePC\s\(1\)\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string82 = /RemotePC\sPerformance\sPrinter\.url/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string83 = /RemotePC\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string84 = /RemotePC\.WebSockets\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string85 = /RemotePC\\REMOTE\~2\.DLL/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string86 = /RemotePCBlackScreenApp\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string87 = /RemotePCCopyPaste\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string88 = /RemotePCDesktop\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string89 = /RemotePCDesktop\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string90 = /RemotePCHDDesktop\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string91 = /RemotePCHDService\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string92 = /remotepclauncher\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string93 = /RemotePCModules\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string94 = /RemotePCPerformanceWebLauncher\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string95 = /RemotePCPerformanceWebLauncher\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string96 = /RemotePCPrinter\.exe\.config/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string97 = /RemotePCPrinting\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string98 = /RemotePCPrintView\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string99 = /RemotePCProxys\.dat/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string100 = /RemotePCService\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string101 = /RemotePCService\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string102 = /RemotePCService_2\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string103 = /RemotePCShortcut\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string104 = /RemotePCSuite\.Model\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string105 = /RemotePCSuite\.Service\.dll/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string106 = /remotepcuiu\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string107 = /RpcApp.{0,1000}TransferClient\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string108 = /RpcApp.{0,1000}TransferServer\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string109 = /rpcdownloader\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string110 = /RPCDownloaderLogFile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string111 = /RPCFireWallRule\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string112 = /RPCFireWallRulelogfile\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string113 = /RPCKeyMouseHandler\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string114 = /RPCPerformanceHealthCheck/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string115 = /rpcperformanceservice\.exe	/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string116 = /RPCPerformanceService\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string117 = /rpcperfviewer\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string118 = /RPCPerfViewer\.log/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string119 = /rpcprinterdownloader\.exe/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string120 = /RPCProxyLatency\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string121 = /RPCsuiteLaunch\.txt/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string122 = /rule\sname\=\"TransferServer\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string123 = /sc\s\sdelete\s\"RPCService\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string124 = /sc\s\sstart\s\"RPCService\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string125 = /sc\s\sstop\s\"RPCService\"/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string126 = /sc\screate\sRPCService\sstart\=auto/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string127 = /sc\sdelete\sViewerService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string128 = /sc\sstart\sViewerService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string129 = /sc\sstop\sViewerService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string130 = /StartRPCPerformanceService/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string131 = /StartRPCPerformanceServiceOnStart/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string132 = /static\.remotepc\.com/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string133 = /Uninstall\sRemotePC\.lnk/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string134 = /viewerhostkeypopup\.exe\s/ nocase ascii wide
        // Description: RemotePC RMM tool - abused by attackers
        // Reference: https://www.remotedesktop.com/
        $string135 = /web1\.remotepc\.com/ nocase ascii wide

    condition:
        any of them
}
