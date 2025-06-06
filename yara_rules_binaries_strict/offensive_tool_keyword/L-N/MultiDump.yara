rule MultiDump
{
    meta:
        description = "Detection patterns for the tool 'MultiDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MultiDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string1 = /\sMultiDump\.exe/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string2 = /\.exe\s\-\-procdump\s\-p\s/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string3 = /\/MultiDump\.exe/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string4 = /\/MultiDump\.git/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string5 = /\[\!\]\sDumping\sLSASS\sRequires\sElevated\sPriviledges\!/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string6 = /\[\!\]\sFailed\sto\sCreate\sProcess\sto\sDump\sSAM/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string7 = /\[\!\]\sFailed\sto\sTransfer\sLSASS\sDump/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string8 = /\[\-\]\sUnable\sto\sRead\sLSASS\sDump/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string9 = /\[\+\]\sLSASS\sdump\sdone\!/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string10 = /\[\+\]\sLSASS\sDump\sRead\:\s/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string11 = /\[i\]\sDumping\sLSASS\sUsing\scomsvcs\.dll/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string12 = /\[i\]\sDumping\sLSASS\sUsing\sProcDump/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string13 = /\[i\]\sSending\sEncrypted\sSAM\sSave/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string14 = /\\lsass\.dmp/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string15 = /\\MultiDump\.c/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string16 = /\\MultiDump\.exe/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string17 = /\\MultiDump\.sln/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string18 = /\\MultiDump\.vcxproj/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string19 = "2C6D323A-B51F-47CB-AD37-972FD051D475" nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string20 = "7ce3b3c16cdaa2dfae51fbcf163ac75947127a9fd5e2d3c588480e3629345e8f" nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string21 = "90229D7D-5CC2-4C1E-80D3-4B7C7289B480" nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string22 = "encrypted LSASS dump" nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string23 = "Error parsing lsass dump with pypykatz" nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string24 = "lsassDumpRetryCount" nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string25 = /ProcDumpHandler\.py\s\-r\s/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string26 = /Public\\lsass\.dmp/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string27 = /pypykatz\.pypykatz/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string28 = /reg\.exe\sexport\sHKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string29 = /reg\.exe\ssave\sHKLM\\/ nocase ascii wide
        // Description: MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly
        // Reference: https://github.com/Xre0uS/MultiDump
        $string30 = "Xre0uS/MultiDump" nocase ascii wide
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
