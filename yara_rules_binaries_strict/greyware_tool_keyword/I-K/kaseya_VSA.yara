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
        $string36 = /PCMONITORMANAGER\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string37 = /PCMonitorSrv\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string38 = /PCMonitorSrv\.exe/ nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string39 = /PCMONITORSRV\.EXE\-.{0,100}\.pf/ nocase ascii wide
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
        $string43 = /PCMONTASK\.EXE\-.{0,100}\.pf/ nocase ascii wide
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
        $string50 = "SC  QUERYEX \"PC Monitor\"" nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string51 = "SC  QUERYEX \"VSAX\"" nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string52 = "'ServiceName'>VSA X</Data>" nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string53 = "'ServiceName'>VSAX</Data>" nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string54 = "'VSA X Manager" nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string55 = "'VSA X Remote Control'" nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string56 = "'VSA X Service'" nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string57 = "'VSA X User Agent'" nocase ascii wide
        // Description: Kaseya VSA (Virtual System Administrator) is a cloud-based IT management and remote monitoring software designed for managed service providers (MSPs) and IT departments -it is abused by attackers
        // Reference: https://www.kaseya.com/products/vsa/
        $string58 = /vsxrc\-client\.dll/ nocase ascii wide
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
