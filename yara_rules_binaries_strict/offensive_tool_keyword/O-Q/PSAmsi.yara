rule PSAmsi
{
    meta:
        description = "Detection patterns for the tool 'PSAmsi' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAmsi"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string1 = /\s\|\sFind\-AmsiSignatures/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string2 = /\s\|\sTest\-ContainsAmsiSignatures/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string3 = /\s\-ScriptString\s.{0,100}\s\-GetMinimallyObfuscated/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string4 = /\s\-ScriptString\s.{0,100}\s\-PSAmsiScanner\s/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string5 = /\s\-ServerUri\s.{0,100}\s\-FindAmsiSignatures/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string6 = /\$PSAmsiScanRequests/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string7 = /\/PSAmsi\.git/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string8 = /\[console\]\:\:WriteLine\(\'Obfuscation\sRocks\!\'\)/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string9 = "051d5f7fb8c577932d243da40e744e1e228d5f1b89c83613aa4e8a8ad5ee6b98" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string10 = "068accaf38e4552f7b761845066b901afca8590c1bdcb66d639d52541a20a79c" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string11 = "2555b58b1d822f73a540ad15f6d6b8a7105f66a7c00233bdd1c03c4b8cc85824" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string12 = "41b565b208250619c33cbb858758cceb6f5382d4d64448eab3b22300257adf4f" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string13 = "4a7242511d6678dc255d9f4651ea4ed2fec74f5293323c2ce6bb23956beb02a4" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string14 = "4e190d43b933586e8abdcbd64e900d02345834bc0ca314b8b8abc86b3c176bd3" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string15 = "527c7882ae3e01133e4230620d1435c40bfbd258fefc39cab74329a20fd0cf04" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string16 = "72cb6dcc8251f18f112f983804a34dc1f651c87614c18ced8a8f0ccf614bca80" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string17 = "7dea0ea9ae8fe294dbe38f27a1e718298ce411f3bcc86084741b8484276ea8a6" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string18 = "8ccf0e4161a841745e5ef8c6a2e46c48420b7eb010aa2aa3468b014e981949a5" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string19 = "93308034f5c3b6c30fa3251382e31f270606f94cb81bcb028edb7d68cd87e73c" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string20 = "9b432d28fab76406a94c7b59e20a71cd65d1bde26b41bcd6d31e02387e8e81cf" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string21 = "a9489baffe0c884e3ef759f05124e99864b3d4072c7011e71522a1197ed309a9" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string22 = "b626dc080fa41c23cf358fae12dfe70ed167a78b9173ae0249d4c02b7fadb34b" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string23 = "cobbr/PSAmsi" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string24 = "dfdb8a1bfa8b93e9c81e8682c57ad011d477ef756de6a97151415059b81f6270" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string25 = "e53f158d-8aa2-8c53-da89-ab75d32c8c01" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string26 = "Find-AmsiAstSignatures " nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string27 = "Find-AmsiPSTokenSignatures " nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string28 = /Find\-AmsiSignatures\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string29 = "Get-MinimallyObfuscated -ScriptPath " nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string30 = "Get-PSAmsiScanResult " nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string31 = "Invoke-PSAmsiScan" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string32 = "New-PSAmsiScanner -" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string33 = /\'Obfu\'\+\'scation\sRo\'\+\'cks\!\'/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string34 = /Out\-ObfuscatedAst\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string35 = /Out\-ObfuscatedStringCommand\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string36 = /Out\-ObfuscatedTokenCommand\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string37 = /PowerShellObfuscator\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string38 = /PSAmsiClient\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string39 = /PSAmsiScanner\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string40 = "Reset-PSAmsiScanCache " nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string41 = /Start\-PSAmsiClient\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string42 = "Start-PSAmsiServer -" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string43 = /Start\-PSAmsiServer\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string44 = "Test-ContainsAmsiAstSignatures " nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string45 = "Test-ContainsAmsiPSTokenSignatures -" nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string46 = "Test-ContainsAmsiSignatures " nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string47 = /Write\-Host\s\(\'Hel\'\+\'lo\sWo\'\+\'rld\!\'\)/ nocase ascii wide
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
