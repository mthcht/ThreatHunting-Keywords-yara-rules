rule S_inject
{
    meta:
        description = "Detection patterns for the tool 'S-inject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S-inject"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string1 = /\/S\-inject\.exe/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string2 = /\/S\-inject\.git/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string3 = /\/S\-inject_x64\.exe/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string4 = /\/S\-inject_x86\.exe/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string5 = /\\S\-inject\.exe/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string6 = /\\S\-inject\.vcxproj/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string7 = /\\S\-inject_x64\.exe/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string8 = /\\S\-inject_x86\.exe/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string9 = "07bbfa80e6278158beec9685f17d0e305a03449433bd0485bcf492a57c480f80" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string10 = "2E98B8D4-7A26-4F04-A95D-2051B0AB884C" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string11 = "7d87848076e10ed06f0a178bfae29e07d10c2d8831c0b4a5c6865b950fb2635c" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string12 = "9220fead7ddb2863404b1fa59bf2ece1de125be39db2661378a8ffd47057b85e" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string13 = "b3fc8195cc5265fe46562d4063d259fe5e56835b06f598be324af18c0adb39b1" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string14 = "c4fa40d25a8a4fc502e9cce4fa6d7ef7847141bda5f2fb7b90bd9f4b43ee5d13" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string15 = "c4fa40d25a8a4fc502e9cce4fa6d7ef7847141bda5f2fb7b90bd9f4b43ee5d13" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string16 = "cd46607d2b9a3046748fea6f99f34ea9342653b82af06e20858a447cc58f0f34" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string17 = "cd46607d2b9a3046748fea6f99f34ea9342653b82af06e20858a447cc58f0f34" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string18 = "d7018d7037ff228d9f8528846861639c1f7c139e7769c893ae350c20098e55e5" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string19 = "Joe1sn/S-inject" nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string20 = /Release\/S\-inject\.exe/ nocase ascii wide
        // Description: Windows injection of x86/x64 DLL and Shellcode
        // Reference: https://github.com/Joe1sn/S-inject
        $string21 = /S\-inject\\S\-inject\.cpp/ nocase ascii wide
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
