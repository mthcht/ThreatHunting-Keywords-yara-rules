rule var0xshell
{
    meta:
        description = "Detection patterns for the tool 'var0xshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "var0xshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string1 = /\sObfuscated\-Code\.py/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string2 = "#Author Yehia Elghaly" nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string3 = /\#Bind\sShell\s\(Client\)\s\(XOR\sAlgorithm\)/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string4 = /\/Obfuscated\-Code\.py/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string5 = /\/var0xshell\.git/
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string6 = /\\Obfuscated\-Code\.py/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string7 = "b80bb505227429df0b61a07d2ab57c02a48043fbd90d4680192b1698e9a2f37a" nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string8 = "e376445d4c432d5f3c61e4584974941028c2975b97ee1461e4f00c65eb09a0ed" nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string9 = "e379046040e17b60f1311e1d406a5bd9e34fd3f8b9e22cbceed612a6c3a689a9" nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string10 = "yehia-mamdouh/var0xshell" nocase ascii wide
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
