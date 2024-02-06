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
        $string2 = /\sstart\srustdesk\:\/\// nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string3 = /\/home\/user\/rustdesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string4 = /\/RustDesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string5 = /\/rustdesk\.git/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string6 = /\/rustdesk\/rustdesk\/releases\// nocase ascii wide
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
        $string15 = /\\rustdesk\-.{0,1000}\-x86_64\.exe/ nocase ascii wide
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
        $string21 = /095e73fc4b115afd77e39a9389ff1eff6bdbff7a/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string22 = /HKEY_CLASSES_ROOT\\rustdesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string23 = /info\@rustdesk\.com/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string24 = /name\=\"RustDesk\sService\"/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string25 = /rs\-ny\.rustdesk\.com/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string26 = /RuntimeBroker_rustdesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string27 = /RustDesk\sService\sis\srunning/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string28 = /rustdesk\-.{0,1000}\.apk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string29 = /rustdesk\-.{0,1000}\.deb/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string30 = /rustdesk\-.{0,1000}\.dmg/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string31 = /rustdesk\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string32 = /rustdesk\-.{0,1000}\-win7\-install\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string33 = /RustDesk\.exe\s/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string34 = /RUSTDESK\.EXE\-.{0,1000}\.pf/ nocase ascii wide
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
        $string43 = /sc\sstart\sRustDesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string44 = /sc\sstop\sRustDesk/ nocase ascii wide

    condition:
        any of them
}
