rule UltraVNC
{
    meta:
        description = "Detection patterns for the tool 'UltraVNC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UltraVNC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string1 = /\sstart\suvnc_service/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string2 = /\sstop\suvnc_service/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string3 = /\sultravnc\.ini\s/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string4 = /\svnc\.ini\s/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string5 = /\\"publisher\\"\:\\"uvnc\sbvba/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string6 = /\/downloads\/ultravnc\.html/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string7 = /\\127\.0\.0\.1\-5900\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string8 = /\\AppData\\Roaming\\.{0,100}\-5900\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string9 = /\\AppData\\Roaming\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string10 = /\\createpassword\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string11 = /\\CurrentVersion\\Uninstall\\Ultravnc2_is1\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string12 = /\\InventoryApplicationFile\\ultravnc_/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string13 = /\\options\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string14 = /\\Services\\EventLog\\Application\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string15 = /\\SOFTWARE\\ORL\\VNCHooks\\Application_Prefs\\WinVNC/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string16 = /\\ultravnc\.cer/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string17 = /\\UltraVNC\.ini/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string18 = /\\uvnc\sbvba\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string19 = /\\uvnc_launch\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string20 = /\\uvnc_settings\.ex/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string21 = /\\uvnc_settings\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string22 = /\\uvnckeyboardhelper\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string23 = /\\vncviewer\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string24 = /\\winvnc\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string25 = /\\winvncsc\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string26 = /\\winwvc\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string27 = /bvba_UltraVNC_.{0,100}_exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string28 = /certutil\.exe.{0,100}\s\-addstore\s\\"TrustedPublisher\\".{0,100}ultravnc\.cer/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string29 = /\'Company\'\>UltraVNC\<\/Data\>/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string30 = /\'Description\'\>VNC\sserver\<\/Data\>/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string31 = /firewall\sadd\sallowedprogram\s.{0,100}vncviewer\.exe.{0,100}\sENABLE\sALL/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string32 = /firewall\sadd\sallowedprogram\s.{0,100}winvnc\.exe.{0,100}\sENABLE\sALL/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string33 = /firewall\sadd\sportopening\sTCP\s5800\svnc5800/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string34 = /firewall\sadd\sportopening\sTCP\s5900\svnc5900/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string35 = /HKCR\\\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string36 = /Program\sFiles\s\(x86\)\\uvnc\sbvba\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string37 = /UltraVNC\sLauncher\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string38 = /ultravnc\smslogonacl/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string39 = /UltraVNC\sRepeater\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string40 = /UltraVNC\sServer\sSettings\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string41 = /UltraVNC\sServer\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string42 = /ultravnc\stestauth/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string43 = /UltraVNC\sViewer\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string44 = /UltraVNC_.{0,100}_X86_Setup/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string45 = /ULTRAVNC_1.{0,100}_X86_SETUP\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string46 = /ultravnc_repeater/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string47 = /ultravnc_server/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string48 = /ultravnc_viewer/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string49 = /VNCviewer\sConfig\sFile/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string50 = /VncViewer\.Config/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string51 = /VNCVIEWER\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string52 = /WinVNC\.exe/ nocase ascii wide
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
