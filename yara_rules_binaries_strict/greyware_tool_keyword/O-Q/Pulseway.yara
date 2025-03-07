rule Pulseway
{
    meta:
        description = "Detection patterns for the tool 'Pulseway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pulseway"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string1 = /\s\<Data\>Received\sRequest\sRun\scommand\s.{0,100}\<\/Data\>/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string2 = /\sPCMonitorManager\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string3 = /\sPCMonitorSrv\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string4 = /\spulseway_x64\.deb/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string5 = /\sPulseway_x64\.msi/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string6 = /\spulseway_x86\.deb/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string7 = /\/etc\/pulseway\/config\.xml/
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string8 = /\/PCMonitorManager\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string9 = /\/PCMonitorSrv\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string10 = /\/pcmrdp\-client\.dll/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string11 = /\/pulseway_x64\.deb/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string12 = /\/Pulseway_x64\.msi/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string13 = /\/pulseway_x86\.deb/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string14 = /\/systemd\/system\/pulseway\.service/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string15 = "/usr/sbin/pulseway"
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string16 = "/usr/sbin/pulsewayd"
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string17 = /\\AppData\\Roaming\\.{0,100}\\RemoteDesktop\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string18 = /\\AppData\\Roaming\\.{0,100}\\uac\.tmp/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string19 = /\\MMSOFT\sDesign\\PC\sMonitor/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string20 = /\\MMSOFT\sDesign\\Pulseway\\/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string21 = /\\PCMonitorManager\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string22 = /\\PCMonitorSrv\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string23 = /\\PCMonitorTypes\.dll/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string24 = /\\pcmrdp\-client\.dll/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string25 = /\\pcmupdate\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string26 = /\\pcmupdate\.exe\.config/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string27 = /\\Pulseway\sRemote\sControl\\/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string28 = /\\Pulseway\\/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string29 = /\\pulseway_x64\.deb/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string30 = /\\Pulseway_x64\.msi/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string31 = /\\pulseway_x86\.deb/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string32 = /\\PulsewayServiceCheck/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string33 = /\\pwyrc\-agent\.dll/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string34 = /\\pwy\-rd\\shell\\open\\command/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string35 = /\\RemoteDesktop_x64\.msi/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string36 = /\\SOFTWARE\\Microsoft\\Tracing\\PCMonitorSrv_RAS/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string37 = /\\Tasks\\PulsewayServiceCheck/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string38 = "<Data>Pulseway Remote Control</Data>" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string39 = /\<Data\>Received\sRequest\sExecute\sautomation\s.{0,100}\sscript\s.{0,100}\sfrom\sdevice\sId/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string40 = /\<Data\>Received\sRequest\sGet\sRD\spool\sscore\s.{0,100}pulseway\.com\/remote/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string41 = "<Provider Name=\"PC Monitor\" />" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string42 = "<Provider Name=\"Pulseway\" />" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string43 = /https\:\/\/.{0,100}\.pulseway\.com\/app\/main\// nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string44 = "Pulseway -- Installation completed successfully" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string45 = "Pulseway -- Removal completed successfully" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string46 = "Pulseway Remote Control -- Installation completed successfully" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string47 = /Pulseway\sRemote\sControl\.lnk/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string48 = /pulseway_x64\.pkg\.tar\.xz/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string49 = /pwyrc\-clip\.exe/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string50 = /rd\-asia\-au\-1\.pulseway\.com/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string51 = /rd\-eu\-de\-1\.pulseway\.com/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string52 = /rd\-eu\-ie\-1\.pulseway\.com/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string53 = /rd\-us\-east\-1\.pulseway\.com/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string54 = /rd\-us\-east\-2\.pulseway\.com/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string55 = /rd\-us\-west\-1\.pulseway\.com/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string56 = /Received\sRequest\sRun\sPowerShell\scommand\s\'.{0,100}\'\sfrom\sdevice\sId/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string57 = /RemoteDesktop\.exe.{0,100}pwy\-rd\:\?token\=/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string58 = "SC  QUERYEX \"PC Monitor\"" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string59 = "service pulseway start" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string60 = "service pulseway stop" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string61 = "ServiceName\">Pulseway</Data>" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string62 = "systemctl start pulseway" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string63 = "systemctl status pulseway" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string64 = "systemctl stop pulseway" nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string65 = /systemprofile\\AppData\\Roaming\\freerdp\\server/ nocase ascii wide
        // Description: Pulseway - remote monitoring and management tool designed for IT administrators to monitor and manage their IT systems and infrastructure remotely - abused by attackers
        // Reference: https://www.pulseway.com/
        $string66 = /www\.pulseway\.com\/download\// nocase ascii wide
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
