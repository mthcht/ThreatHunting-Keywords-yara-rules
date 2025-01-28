rule NimScan
{
    meta:
        description = "Detection patterns for the tool 'NimScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimScan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string1 = /\sNimScan\.exe/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string2 = /\sNimScan\.nim/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string3 = /\/NimScan\.exe/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string4 = /\/NimScan\.git/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string5 = /\/NimScan\.nim/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string6 = /\\NimScan\.exe/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string7 = /\\NimScan\.nim/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string8 = ">NimScan<" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string9 = "162b04e6c89653b10bd38def513051067393d9080afd777210b0ce44f1a7d9fe" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string10 = "394daa8e246f41baa4f37b1721991248f003766f079e671b8e51794259818c91" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string11 = "662d9dd3a88b004a8eb3e5944457a1661ec7a28dd4695d6f96fbcbf095ba057a" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string12 = "72605e93bf880f32e23eb3b5d1ab30a66c7a2beb3c195d5d2bc5738e1b7ddbf5" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string13 = "9084acb8a61d051af66cad27ceb81976c45c4378e9846a22d8befe3294217e7d" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string14 = "b6911a2d3730f3bbcd89d503ac1226d6e6172cb49d3c92d04df933ef3c9e1531" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string15 = "ca96a1f8836f1c1afdf2c410e9d686f7beca7784e859971a493a6610522708e2" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string16 = "dacdb4976fd75ab2fd7bb22f1b2f9d986f5d92c29555ce2b165c020e2816a200" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string17 = "e43d66b7a4fa09a0714c573fbe4996770d9d85e31912480e73344124017098f9" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string18 = "elddy/NimScan" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string19 = /\-l\:NimScanToC\.a\s/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string20 = "netsh advfirewall firewall add rule name='NimScan'" nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string21 = /NimScan\s.{0,100}\s\-p\:/ nocase ascii wide
        // Description: Really fast port scanner (With filtered option - Windows support only)
        // Reference: https://github.com/elddy/NimScan
        $string22 = "NimScan finished in:" nocase ascii wide
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
