rule Radmin
{
    meta:
        description = "Detection patterns for the tool 'Radmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Radmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string1 = /\/Radmin\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string2 = /\/Radmin_Server_.{0,100}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string3 = /\/Radmin_Viewer_.{0,100}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string4 = /\/Radmin_VPN_1\..{0,100}\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string5 = /\/rserver3\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string6 = /\\AppData\\Local\\Temp\\.{0,100}_Radmin_3\..{0,100}\.zip/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string7 = /\\AppData\\Roaming\\Radmin/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string8 = /\\Radmin\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string9 = /\\RADMIN\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string10 = /\\Radmin\\radmin\.rpb/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string11 = /\\Radmin_Server_.{0,100}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string12 = /\\Radmin_Viewer_.{0,100}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string13 = /\\Radmin_VPN_1\..{0,100}\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string14 = /\\rserver3\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string15 = /\\rsetup64\.exe.{0,100}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string16 = /\\rsl\.exe\s\/setup/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string17 = /\\rsl\.exe.{0,100}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string18 = /\\Start\sMenu\\Programs\\Radmin\sServer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string19 = /\\Start\sMenu\\Programs\\Radmin\sViewer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string20 = /\\SysWOW64\\rserver30\\FamItrf2/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string21 = /\\SysWOW64\\rserver30\\FamItrfc/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string22 = /\\Windows\\SysWOW64\\rserver30\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string23 = /\>Famatech\sCorp\.\</ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string24 = /download\.radmin\.com/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string25 = /download\.radmin\-vpn\.com/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string26 = /HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Radmin\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string27 = "netsh advfirewall firewall add rule name=\"Radmin Server " nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string28 = /Program\sFiles\s\(x86\)\\Radmin\sViewer\s3\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string29 = "radmin /connect:" nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string30 = "Radmin Server V3" nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string31 = /Radmin\sViewer\s3\\CHATLOGS\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string32 = /Radmin\sViewer\s3\\rchatx\.dll/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string33 = /radmin\.exe.{0,100}\s\/connect\:/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string34 = "rserver3 /start" nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string35 = "rserver3 /stop" nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string36 = /rserver3\.exe.{0,100}\/start/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string37 = /rserver3\.exe.{0,100}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string38 = /Settings\sfor\sRadmin\sServer\.lnk/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string39 = /Stop\sRadmin\sServer\.lnk/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string40 = /support\.radmin\.com/ nocase ascii wide
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
