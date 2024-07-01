rule kaseya_VSA
{
    meta:
        description = "Detection patterns for the tool 'kaseya VSA' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kaseya VSA"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string1 = /\spcmontask\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string2 = /\sRemoteDesktop\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string3 = /\sVSAX_x64\.msi/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string4 = /\.vsax\.net/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string5 = /\/pcmontask\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string6 = /\/RemoteDesktop\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string7 = /\/VSAX_x64\.msi/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string8 = /\/vsxrc\-clip\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string9 = /\\AppData\\Roaming\\freerdp/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string10 = /\\AppData\\Roaming\\VSA\sX/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string11 = /\\CurrentControlSet\\Services\\VSAX/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string12 = /\\Kaseya\\PC\sMonitor\\/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string13 = /\\PC\sMonitor\\Addons/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string14 = /\\pcmontask\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string15 = /\\pcmupdate\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string16 = /\\RemoteDesktop\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string17 = /\\Services\\EventLog\\Application\\VSA\sX/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string18 = /\\Services\\EventLog\\Application\\VSAX/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string19 = /\\SOFTWARE\\Kaseya\\/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string20 = /\\TaskCache\\Tree\\VSA\sXServiceCheck/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string21 = /\\VSA\sX\sManager\.lnk/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string22 = /\\VSA\sX\sRemote\sControl\.lnk/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string23 = /\\VSA\sX\sRemote\sControl\\/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string24 = /\\VSA\sX\\watchdog\.bat/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string25 = /\\VSA\sXServiceCheck/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string26 = /\\VSAX\\working/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string27 = /\\VSAX_x64\.msi/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string28 = /\\vsxrc\-clip\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string29 = /KASEYA\sHOLDINGS\sINC\./ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string30 = /managedsupport\.kaseya\.net/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string31 = /PCMonitorCfg\.dll/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string32 = /PCMonitorClient\.dll/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string33 = /PCMonitorEng\.dll/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string34 = /PCMonitorManager\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string35 = /PCMonitorManager\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string36 = /PCMONITORMANAGER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string37 = /PCMonitorSrv\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string38 = /PCMonitorSrv\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string39 = /PCMONITORSRV\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string40 = /PCMonitorSrv\.InstallState/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string41 = /PCMonitorTypes\.dll/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string42 = /pcmontask\.exe\s/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string43 = /PCMONTASK\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string44 = /pcmrdp\-client\.dll/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string45 = /Program\sFiles\\VSA\sX\\/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string46 = /ProgramData\\Kaseya\\/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string47 = /RemoteDesktop\.exe\s/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string48 = /RemoteDesktop_x64\s\(1\)\.msi/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string49 = /RemoteDesktop_x64\.msi/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string50 = /SC\s\sQUERYEX\s\"PC\sMonitor\"/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string51 = /SC\s\sQUERYEX\s\"VSAX\"/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string52 = /\'ServiceName\'\>VSA\sX\<\/Data\>/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string53 = /\'ServiceName\'\>VSAX\<\/Data\>/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string54 = /\'VSA\sX\sManager/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string55 = /\'VSA\sX\sRemote\sControl\'/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string56 = /\'VSA\sX\sService\'/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string57 = /\'VSA\sX\sUser\sAgent\'/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string58 = /vsxrc\-client\.dll/ nocase ascii wide

    condition:
        any of them
}
