rule BrowsingHistoryView
{
    meta:
        description = "Detection patterns for the tool 'BrowsingHistoryView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BrowsingHistoryView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string1 = /\.exe\s\s\/HistorySource\s1\s\/SaveDirect\s\/scomma\s/ nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string2 = /\.exe\s\/HistorySource\s1\s\/LoadChrome\s1\s\/shtml\s/ nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string3 = ">BrowsingHistoryView<" nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string4 = "19a43d7ebc516f2344e6ffac66205d54cbde907e2eb1fb6171934d292524c5c7" nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string5 = "1cc45acf429d705ee592af1c9e56ac25f5b5acbc27fe555db5007c8be9cc4c42" nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string6 = "9f65528998b39f2e7239f89a56ded47ea865eea2d6b82b300cd5de7e62072cf0" nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string7 = /BrowsingHistoryView\.cfg/ nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string8 = /BrowsingHistoryView\.exe/ nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string9 = /BROWSINGHISTORYVIEW\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string10 = /browsinghistoryview\.zip/ nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string11 = /browsinghistoryview\-x64\.zip/ nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string12 = "c5bcfd00d0b8fda7c4b20cdc9649713d9f01dd12f61ce8ee9c45ec424a6bbdf2" nocase ascii wide
        // Description: BrowsingHistoryView is a utility that reads the history data of different Web browsers
        // Reference: https://www.nirsoft.net/utils/browsing_history_view.html
        $string13 = /nirsoft\.net\/utils\/browsing_history_view\.html/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
