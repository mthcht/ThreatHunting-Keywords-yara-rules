rule DataBouncing
{
    meta:
        description = "Detection patterns for the tool 'DataBouncing' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DataBouncing"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string1 = /\sdeadPool\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string2 = /\sexfilGui\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string3 = /\snightCrawler\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string4 = /\swget\s\\"https\:\/\/.{0,100}\/interactshbuild/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string5 = /\/DataBouncing\.git/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string6 = /\/deadPool\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string7 = /\/exfilGui\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string8 = /\/nightCrawler\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string9 = /\\deadPool\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string10 = /\\exfilGui\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string11 = /\\nightCrawler\.ps1/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string12 = /bash\s\.\/bounce\.sh/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string13 = /clndh3qilvdv6403g1n0hs3rhd6xpfmjn\.oast\.online/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string14 = /DataBouncing\-main\.zip/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string15 = /exfil\s\-regex.{0,100}\s\-domain.{0,100}\-url\s.{0,100}\s\-filepath\s/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string16 = /Find\-Secret\s\-FilePath\s\.\/logs\.txt\s\-Regex\s/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string17 = /https\:\/\/unit259\.fyi\/db/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string18 = /irm\sunit259\.fyi\/dbgui\s\|\siex/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string19 = /nightCrawler\.ps1\s/ nocase ascii wide
        // Description: Data Bouncing is a technique for transmitting data between two endpoints using DNS lookups and HTTP header manipulation
        // Reference: https://github.com/Unit-259/DataBouncing
        $string20 = /Unit\-259\/DataBouncing/ nocase ascii wide
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
