rule NetshHelperBeacon
{
    meta:
        description = "Detection patterns for the tool 'NetshHelperBeacon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetshHelperBeacon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string1 = /\/NetshHelperBeacon\.git/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string2 = /\\NetshHelperBeacon\.cpp/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string3 = /\\NetshHelperBeacon\.dll/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string4 = /\\NetshHelperBeacon\.lib/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string5 = /\\NetshHelperBeacon\.log/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string6 = /\\NetshHelperBeacon\.pdb/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string7 = /\\NetshHelperBeacon\\/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string8 = /\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x48\\x8b\\x52\\x20\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string9 = /\\xfc\\xe8\\x89\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x0f\\xb7\\x4a\\x26\\x31\\xff\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\xe2\\xf0\\x52\\x57\\x8b\\x52\\x10\\x8b\\x42\\x3c\\x01\\xd0\\x8b\\x40\\x78\\x85\\xc0\\x74\\x4a\\x01\\xd0\\x50\\x8b\\x48\\/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string10 = "3BB0CD58-487C-4FEC-8001-607599477158" nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string11 = "93b20a7961c9986baf181d1a1635b33b87735f75d046c6dcdd5d412a55832d6f" nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string12 = "9ecca3b6c787675d74bbfaa0e3ded77d448a0de4fe51c3c29c07cf3b04b8b71d" nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string13 = "a84e1abea8327bcede6dfb79b50b36780f2e1cdb8166002d75c070574a83738f" nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string14 = /NetshHelperBeacon\.exe/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string15 = "outflanknl/NetshHelperBeacon" nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string16 = "Simple code for creating a DLL for netsh helper DLLs" nocase ascii wide
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
