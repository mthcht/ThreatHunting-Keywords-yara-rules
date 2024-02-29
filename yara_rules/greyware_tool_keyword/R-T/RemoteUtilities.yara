rule RemoteUtilities
{
    meta:
        description = "Detection patterns for the tool 'RemoteUtilities' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemoteUtilities"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string1 = /\sConnection\s\#.{0,1000}\.\sConnection\sto\s\".{0,1000}\"\sestablished\.\sMode\:\s\<Remote\scontrol\>\./ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string2 = /\sConnection\s\#.{0,1000}\.\sConnection\sto\s\".{0,1000}\"\.\sSecurity\scheck\s\-\sOK\.\sMode\:\s\s\<Inventory\smanager\>/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string3 = /\sConnection\s\#.{0,1000}\.\sConnection\sto\s\".{0,1000}\"\.\sSecurity\scheck\s\-\sOK\.\sMode\:\s\<Command\s\(command\:\s.{0,1000}\)\>/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string4 = /\sConnection\s\#.{0,1000}\.\sDirect\sconnection\sto\s.{0,1000}\s\(.{0,1000}\:5650\)\./ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string5 = /\s\-name\:.{0,1000}\s\-password\:.{0,1000}\s\-remoteexecute\s\-filename/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string6 = /\.remoteutilities\.com/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string7 = /\/host\-7\.2\.2\.0\.msi/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string8 = /\/rfusclient\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string9 = /\/rutserv\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string10 = /\/rutview\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string11 = /\/usr\/bin\/r\-agent/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string12 = /\/usr\/bin\/r\-viewer/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string13 = /\/usr\/share\/applications\/r\-agent\.desktop/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string14 = /\/usr\/share\/applications\/r\-viewer\.desktop/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string15 = /\/VPDAgent\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string16 = /\\.{0,1000}\-.{0,1000}\-.{0,1000}_rut\-.{0,1000}\.zip\.3bf/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string17 = /\\.{0,1000}\-internet\-id\-log\.csv/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string18 = /\\AppData\\Local\\Downloaded\sInstallations\\.{0,1000}\\server\-3\.3\.5\.0\.msi/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string19 = /\\AppData\\Local\\Downloaded\sInstallations\\.{0,1000}\\viewer\-7\.2\.2\.0\.msi/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string20 = /\\AppData\\Local\\Temp\\.{0,1000}\\server\-3\.3\.5\.0\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string21 = /\\AppData\\Local\\Temp\\.{0,1000}\\server\-3\.3\.5\.0\.msi/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string22 = /\\AppData\\Local\\Temp\\rutserv/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string23 = /\\AppData\\Roaming\\Remote\sUtilities\sFiles/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string24 = /\\CurrentControlSet\\Services\\MiniInternetIdService/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string25 = /\\CurrentVersion\\Devices\\Remote\sUtilities\sPrinter/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string26 = /\\drivers\\x64\\rupdui\.dll/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string27 = /\\host\-7\.2\.2\.0\.msi/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string28 = /\\InternetIdService\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string29 = /\\InternetIdService_.{0,1000}\-.{0,1000}\-.{0,1000}\.txt/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string30 = /\\Logs\\rut_log_.{0,1000}\.html/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string31 = /\\Printers\\Remote\sUtilities\sPrinter\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string32 = /\\ProgramData\\Remote\sUtilities/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string33 = /\\remote\sutilities\s\-\shost\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string34 = /\\Remote\sUtilities\s\-\sHost\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string35 = /\\remote\sutilities\sagent\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string36 = /\\Remote\sUtilities\sAgent\\Logs/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string37 = /\\Remote\sUtilities\sFiles\\rdp_connections\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string38 = /\\Remote\sUtilities\sServer\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string39 = /\\Remote\sUtilities\\Logs/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string40 = /\\Remote\sUtilities\\MiniInternetId/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string41 = /\\rfusclient\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string42 = /\\rutserv\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string43 = /\\rutview\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string44 = /\\ru\-viewer\-portable\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string45 = /\\SOFTWARE\\Usoris\\Remote\sUtilities\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string46 = /\\spool\\drivers\\x64\\rupd\./ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string47 = /\\System32\\rupdpm\.dll/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string48 = /\\Two\sPilots\\Agent\\Remote\sUtilities\sPrinter/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string49 = /\\unidrv_rupd\.dll/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string50 = /\\unidrv_rupd\.hlp/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string51 = /\\unidrvui_rupd\.dll/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string52 = /\\unires_vpd\.dll/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string53 = /\\viewer\-portable\-7\.2\.2\.0\\/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string54 = /\\VPDAgent\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string55 = /\<a\shref\=\"rutils\:/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string56 = /\<Data\>Product\:\sRemote\sUtilities\s\-\sHost\s\-\-\s/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string57 = /\<Data\>Remote\sUtilities\s\-\sHost\<\/Data\>/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string58 = /\<Data\>Remote\sUtilities\sServer\</ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string59 = /\<Data\>Removed\sRemote\sUtilities\s\-\sHost\.\<\/Data\>/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string60 = /\>Installed\sRemote\sUtilities\s\-\sViewer\./ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string61 = /\>Installed\sRemote\sUtilities\sServer\.\<\// nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string62 = /\>Product\:\sRemote\sUtilities\s\-\sViewer\s\-\-\s/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string63 = /\>Product\:\sRemote\sUtilities\sServer\s\-\-\s/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string64 = /\>Remote\sUtilities\s\-\sViewer\<\// nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string65 = /InternetIdService\.exe/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string66 = /Program\sFiles\s\(x86\)\\Common\sFiles\\Two\sPilots/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string67 = /Remote\sUtilities\sPty\s\(Cy\)\sLtd\./ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string68 = /RemoteAdmin\.RemoteUtilities/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string69 = /rfusclient\.exe\s/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string70 = /rutserv\.exe\s/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string71 = /rutserv\.exe\s\// nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string72 = /rutview\.exe\s/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string73 = /rutview\.exe\s\-/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string74 = /server\.remoteutilities\.com/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string75 = /Trojan\.RemoteUtilitiesRAT/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string76 = /Uninstall\sRemote\sUtilities\s\-\sViewer\.lnk/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string77 = /Uninstall\sRemote\sUtilities\sServer\.lnk/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string78 = /Uninstall\sRemote\sUtilities\.lnk/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string79 = /update\.remoteutilities\.net/ nocase ascii wide

    condition:
        any of them
}
