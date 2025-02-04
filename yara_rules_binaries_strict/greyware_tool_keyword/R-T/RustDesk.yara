rule RustDesk
{
    meta:
        description = "Detection patterns for the tool 'RustDesk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustDesk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string1 = /\sRustDesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string2 = " start rustdesk://" nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string3 = "/home/user/rustdesk"
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string4 = /\/RustDesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string5 = /\/rustdesk\.git/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string6 = "/rustdesk/rustdesk/releases/" nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string7 = /\\\.rustdesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string8 = /\\\\RustDeskIddDriver/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string9 = /\\AppData\\Local\\rustdesk\\/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string10 = /\\config\\RustDesk\.toml/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string11 = /\\config\\RustDesk_local\./ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string12 = /\\CurrentVersion\\Uninstall\\RustDesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string13 = /\\librustdesk\.dll/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string14 = /\\ProgramData\\RustDesk\\/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string15 = /\\rustdesk\-.{0,100}\-x86_64\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string16 = /\\RustDesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string17 = /\\RustDesk\.lnk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string18 = /\\RustDesk\\query/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string19 = /\\RustDeskIddDriver\\/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string20 = /\\test_rustdesk\.log/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string21 = "095e73fc4b115afd77e39a9389ff1eff6bdbff7a" nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string22 = /HKEY_CLASSES_ROOT\\rustdesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string23 = /info\@rustdesk\.com/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string24 = "name=\"RustDesk Service\"" nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string25 = /rs\-ny\.rustdesk\.com/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string26 = /RuntimeBroker_rustdesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string27 = "RustDesk Service is running" nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string28 = /rustdesk\-.{0,100}\.apk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string29 = /rustdesk\-.{0,100}\.deb/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string30 = /rustdesk\-.{0,100}\.dmg/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string31 = /rustdesk\-.{0,100}\.rpm/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string32 = /rustdesk\-.{0,100}\-win7\-install\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string33 = /RustDesk\.exe\s/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string34 = /RUSTDESK\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string35 = /RustDesk_hwcodec\./ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string36 = /RustDesk_install\.bat/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string37 = /rustdesk_portable\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string38 = /RustDesk_rCURRENT\.log/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string39 = /RustDesk_uninstall\.bat/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string40 = /RustDeskIddDriver\.cer/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string41 = /RustDeskIddDriver\.dll/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string42 = /rustdesk\-portable\-packer\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string43 = "sc start RustDesk" nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string44 = "sc stop RustDesk" nocase ascii wide
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
