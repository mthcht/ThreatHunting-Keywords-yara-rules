rule Google_Remote_Desktop
{
    meta:
        description = "Detection patterns for the tool 'Google Remote Desktop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Google Remote Desktop"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string1 = " chrome-remote-desktop@" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string2 = /\.chrome\-remote\-desktop\-session/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string3 = "/system/chrome-remote-desktop@" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string4 = /\\Chrome\sRemote\sDesktop\\host\.json/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string5 = /\\Google\\Chrome\sRemote\sDesktop\\/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string6 = /\\pipe\\chrome_remote_desktop/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string7 = /\\remote_assistance_host\.exe/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string8 = /\\remoting_desktop\.exe/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string9 = /\\remoting_host\.exe/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string10 = /\\remoting_native_messaging_host\.exe/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string11 = /\\remoting_start_host\.exe/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string12 = "<Data>Product: Chrome Remote Desktop Host" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string13 = "<Provider Name=\"chromoting\" />" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string14 = /Channel\sIP\sfor\sclient\:\s.{0,100}\@gmail\.com\/chromoting/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string15 = "Chrome remote desktop installation completed" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string16 = /chrome\-remote\-desktop\.service/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string17 = /chrome\-remote\-desktop_current_amd64\.deb/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string18 = /chromeremotedesktophost\.msi/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string19 = "export CHROME_REMOTE_DESKTOP_DEFAULT_DESKTOP_SIZES" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string20 = "-Force Stop-Process -Name remote_webauthn" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string21 = /google\-chrome\-stable_current_amd64\.deb/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string22 = /https\:\/\/remotedesktop\.google\.com\/_\/oauthredirect/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string23 = /https\:\/\/remotedesktop\.google\.com\/headless/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string24 = "inomeogfingihgjfjlpeplalcfajhgai" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string25 = /remotedesktop\.google\.com\/access/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string26 = /remotedesktop\.google\.com\/support/ nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string27 = "Stop-Process -Force -Name remote_assistance_host" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string28 = "Stop-Process -Force -Name remote_assistance_host_uiaccess" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string29 = "Stop-Process -Force -Name remoting_native_messaging_host" nocase ascii wide
        // Description: Google Chrome Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string30 = "SYSLOG_IDENTIFIER=chrome-remote-desktop" nocase ascii wide
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
